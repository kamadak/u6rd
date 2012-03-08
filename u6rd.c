/* $Id$ */
/*
 * Copyright (c) 2012 KAMADA Ken'ichi.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if_tun.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "version.h"
#include "util.h"

#define TUN_HEAD_LEN	4		/* TUNSIFHEAD */

struct ipv4_header {
	uint8_t ver_hlen;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t cksum;
	uint8_t src[4];
	uint8_t dst[4];
};

struct ipv6_header {
	uint32_t ver_class_label;
	uint16_t len;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t src[16];
	uint8_t dst[16];
};

struct connection {
	struct in6_addr prefix;
	int prefixlenbyte;
	struct in_addr myv4;
	struct sockaddr_in relay;
	int fd_tun;
	int fd_raw;
};

struct options {
	int debug;
	int foreground;
	const char *user;
};

static void usage(void);
static void version(void);
static int parse_prefix(struct in6_addr *prefix, int *prefixlen,
    char *prefixstr);
static int parse_relay(struct sockaddr_in *relay, const char *relaystr);
static int open_tun(const char *devstr);
static int open_raw(struct in_addr *myv4, const char *myv4str);
static int open_sigxfr(void);
static void sighandler(int signo);
static int set_nonblocking(int fd);
static int loop(struct connection *c);
static void tun2raw(struct connection *c);
static void raw2tun(struct connection *c);
static int reject_v4(const uint8_t *addr4);
static int reject_v6(const uint8_t *addr6);
static const char *addr42str(const uint8_t *addr4);
static const char *addr62str(const uint8_t *addr6);

static uint32_t load32(const char *buf);
static void store32(char *buf, uint32_t val);

static void dump(const char *ptr, size_t len);

static struct options options;
static int sigxfr[2];

int
main(int argc, char *argv[])
{
	struct connection con;
	char *devstr, *prefixstr, *relaystr, *myv4str;
	int c;

	setprogname(argv[0]);

	while ((c = getopt(argc, argv, "dFhu:V")) != -1) {
		switch (c) {
		case 'd':
			options.debug++;
			break;
		case 'F':
			options.foreground = 1;
			break;
		case 'h':
			usage();
			/* NOTREACHED */
		case 'u':
			options.user = optarg;
			break;
		case 'V':
			version();
			/* NOTREACHED */
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 4)
		usage();
	devstr = argv[0];
	prefixstr = argv[1];
	relaystr = argv[2];
	myv4str = argv[3];

	openlog(NULL, LOG_PERROR, LOG_DAEMON);
	if (options.debug == 0)
		setlogmask(LOG_UPTO(LOG_INFO));

	if (parse_prefix(&con.prefix, &con.prefixlenbyte, prefixstr) == -1)
		exit(1);
	if (parse_relay(&con.relay, relaystr) == -1)
		exit(1);

	if ((con.fd_tun = open_tun(devstr)) == -1)
		exit(1);
	if ((con.fd_raw = open_raw(&con.myv4, myv4str)) == -1)
		exit(1);
	if (open_sigxfr() == -1)
		exit(1);

	if (!options.foreground && make_pidfile() == -1)
		exit(1);
	if (options.user != NULL && run_as(options.user) == -1) {
		cleanup_pidfile();
		exit(1);
	}
	if (!options.foreground) {
		if (daemon(0, 0) == -1) {
			LERR("daemon: %s", strerror(errno));
			cleanup_pidfile();
			exit(1);
		}
		openlog(NULL, 0, LOG_DAEMON);
	}
	if (!options.foreground && write_pidfile() == -1) {
		cleanup_pidfile();
		exit(1);
	}

	LNOTICE(PROGVERSION " started");
	if (loop(&con) == -1) {
		LNOTICE(PROGVERSION " aborting");
		exit(1);
	}
	LNOTICE(PROGVERSION " exiting");
	cleanup_pidfile();
	exit(0);
}

static void
usage(void)
{
	printf("usage: %s [-dFhV] [-u user] /dev/tunN prefix/prefixlen relay_v4_addr my_v4_addr\n",
	    getprogname());
	exit(1);
}

static void
version(void)
{
	printf(PROGVERSION "\n");
	exit(1);
}

static int
parse_prefix(struct in6_addr *prefix, int *prefixlenbyte, char *prefixstr)
{
	char *p;
	int prefixlen, ret;

	if ((p = strchr(prefixstr, '/')) == NULL) {
		LERR("%s: prefixlen is not specified", prefixstr);
		return -1;
	}
	*p++ = '\0';
	ret = inet_pton(AF_INET6, prefixstr, prefix);
	if (ret == -1) {
		LERR("%s: %s", prefixstr, strerror(errno));
		return -1;
	} else if (ret != 1) {
		LERR("%s: failed to parse", prefixstr);
		return -1;
	}
	prefixlen = atoi(p);		/* XXX overflow */
	/* FP + TLA uses 16 bits.  Not longer than 32 [RFC5569 3]. */
	if (prefixlen < 16 || prefixlen > 32) {
		LERR("prefixlen must be between 16 and 32");
		return -1;
	}
	if (prefixlen % 8 != 0) {
		LERR("prefixlen that is not a multiple of 8 is "
		    "not implemented");
		return -1;
	}
	*prefixlenbyte = prefixlen / 8;
	return 0;
}

static int
parse_relay(struct sockaddr_in *relay, const char *relaystr)
{
	struct addrinfo hints, *res0;
	int gairet;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IPV6;
	hints.ai_flags = AI_NUMERICHOST;
	gairet = getaddrinfo(relaystr, NULL, &hints, &res0);
	if (gairet != 0) {
		LERR("getaddrinfo: %s: %s", relaystr, gai_strerror(gairet));
		return -1;
	}
	if (sizeof(*relay) != res0->ai_addrlen) {
		LERR("length of sockaddr_in mismatch");
		freeaddrinfo(res0);
		return -1;
	}
	*relay = *(struct sockaddr_in *)res0->ai_addr;
	freeaddrinfo(res0);
	return 0;
}

static int
open_tun(const char *devstr)
{
	int fd, on;

	on = 1;

	if ((fd = open(devstr, O_RDWR, 0)) == -1) {
		LERR("open: %s: %s", devstr, strerror(errno));
		return -1;
	}
	/*
	 * Requied (at least) on NetBSD to receive non-IPv4 packets.
	 * If IFHEAD is set, protocol family (4 bytes) is prepended to a
	 * packet.
	 */
	if (ioctl(fd, TUNSIFHEAD, &on) == -1) {
		LERR("ioctl(TUNSIFHEAD): %s: %s", devstr, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int
open_raw(struct in_addr *myv4, const char *myv4str)
{
	struct addrinfo hints, *res0;
	int fd, gairet;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IPV6;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	gairet = getaddrinfo(myv4str, NULL, &hints, &res0);
	if (gairet != 0) {
		LERR("getaddrinfo: %s: %s", myv4str, gai_strerror(gairet));
		return -1;
	}
	if (res0->ai_family != AF_INET) {
		LERR("address family mismatch");
		freeaddrinfo(res0);
		return -1;
	}
	*myv4 = ((struct sockaddr_in *)res0->ai_addr)->sin_addr;

	if ((fd = socket(PF_INET, SOCK_RAW, IPPROTO_IPV6)) == -1) {
		LERR("socket: %s", strerror(errno));
		freeaddrinfo(res0);
		return -1;
	}
	if (bind(fd, res0->ai_addr, res0->ai_addrlen) == -1) {
		LERR("bind: %s", strerror(errno));
		freeaddrinfo(res0);
		close(fd);
		return -1;
	}

	freeaddrinfo(res0);
	return fd;
}

static int
open_sigxfr(void)
{
	struct sigaction sa;

	if (pipe(sigxfr) == -1) {
		LERR("pipe: %s", strerror(errno));
		return -1;
	}
	if (set_nonblocking(sigxfr[1]) == -1) {
		close(sigxfr[0]);
		close(sigxfr[1]);
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &sighandler;
	sa.sa_flags = SA_RESTART;
	(void)sigaction(SIGHUP, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);
	return 0;
}

static void
sighandler(int signo)
{
	(void)write(sigxfr[1], &signo, sizeof(signo));
}

static int
set_nonblocking(int fd)
{
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		LERR("fcntl(F_GETFL): %s", strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		LERR("fcntl(O_NONBLOCK): %s", strerror(errno));
		return -1;
	}
	return 0;
}

static int
loop(struct connection *c)
{
	fd_set rfds, rfds0;
	int maxfd, signo, ret;

	FD_ZERO(&rfds0);
	FD_SET(c->fd_tun, &rfds0);
	FD_SET(c->fd_raw, &rfds0);
	FD_SET(sigxfr[0], &rfds0);
	maxfd = c->fd_tun > c->fd_raw ? c->fd_tun : c->fd_raw;
	maxfd = sigxfr[0] > maxfd ? sigxfr[0] : maxfd;

	for (;;) {
		rfds = rfds0;
		ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			LERR("select: %s", strerror(errno));
			return -1;
		}
		if (FD_ISSET(c->fd_tun, &rfds))
			tun2raw(c);
		if (FD_ISSET(c->fd_raw, &rfds))
			raw2tun(c);
		if (FD_ISSET(sigxfr[0], &rfds)) {
			if (read(sigxfr[0], &signo, sizeof(signo)) == -1) {
				LERR("read: %s", strerror(errno));
				return -1;
			}
			switch (signo) {
			case SIGHUP:
				break;
			case SIGTERM:
			case SIGINT:
				return 0;
			default:
				LERR("unexpected signal %d", signo);
				break;
			}
		}
	}
	/* NOTREACHED */
	return 0;
}

static void
tun2raw(struct connection *c)
{
	char buf[2048];
	struct sockaddr_in direct, *dst;
	struct ipv6_header *ip6;
	unsigned long family;
	size_t ret;

	if ((ret = read(c->fd_tun, buf, sizeof(buf))) == (size_t)-1) {
		LERR("read from tun: %s", strerror(errno));
		return;
	}
	if (ret == sizeof(buf)) {
		LDEBUG("tun2raw: packet too big");
		return;
	}

	if (options.debug > 1) {
		fprintf(stderr, "tun2raw:\n");
		dump(buf, ret);
	}

	/*
	 * We can encapsulate only IPv6 packets.
	 */
	if (ret < TUN_HEAD_LEN) {
		LDEBUG("tun2raw: no address family");
		return;
	}
	if ((family = load32(buf)) != AF_INET6) {
		LDEBUG("tun2raw: non-IPv6 packet (%lu)", family);
		return;
	}

	if (ret - TUN_HEAD_LEN < sizeof(*ip6)) {
		LDEBUG("tun2raw: no IPv6 header (%zu)", ret - TUN_HEAD_LEN);
		return;
	}
	ip6 = (struct ipv6_header *)(buf + TUN_HEAD_LEN);

	/*
	 * Check if the embedded address in the source IPv6 packet matches
	 * with my IPv4 address.  If not, the response will not reach me.
	 */
	if (memcmp(&c->prefix, ip6->src, c->prefixlenbyte) != 0 ||
	    memcmp(&c->myv4, ip6->src + c->prefixlenbyte, 4) != 0) {
		LDEBUG("tun2raw: source is not me (%s)", addr62str(ip6->src));
		return;
	}

	/*
	 * Check the IPv6 destination.  If the destination is within
	 * the prefix, send an encapsulated packet to the corresponding
	 * router directly.  Otherwise, send it to the relay router.
	 */
	if (memcmp(&c->prefix, ip6->dst, c->prefixlenbyte) == 0) {
		if (reject_v4(ip6->dst + c->prefixlenbyte)) {
			LDEBUG("tun2raw: reject IPv4 destination (%s)",
			    addr42str(ip6->dst + c->prefixlenbyte));
			return;
		}
		/* Send to the direct peer. */
		direct = c->relay;
		memcpy(&direct.sin_addr, ip6->dst + c->prefixlenbyte, 4);
		dst = &direct;
	} else {
		if (reject_v6(ip6->dst)) {
			LDEBUG("tun2raw: reject IPv6 destination (%s)",
			    addr62str(ip6->dst));
			return;
		}
		/* Send to the relay. */
		dst = &c->relay;
	}

	if ((ret = sendto(c->fd_raw, buf + TUN_HEAD_LEN, ret - TUN_HEAD_LEN, 0,
	    (struct sockaddr *)dst, sizeof(*dst))) == (size_t)-1) {
		LERR("write to raw: %s", strerror(errno));
		return;
	}
	LDEBUG("%zu bytes written to raw", ret);
}

static void
raw2tun(struct connection *c)
{
	char buf[2048];
	struct ipv4_header *ip4;
	struct ipv6_header *ip6;
	size_t skip, ret;

	if ((ret = recv(c->fd_raw, buf, sizeof(buf), 0)) == (size_t)-1) {
		LERR("read from raw: %s", strerror(errno));
		return;
	}
	if (ret == sizeof(buf)) {
		LDEBUG("raw2tun: packet too big");
		return;
	}

	if (options.debug > 1) {
		fprintf(stderr, "raw2tun:\n");
		dump(buf, ret);
	}

	if (ret < sizeof(*ip4)) {
		LDEBUG("raw2tun: no IPv4 header (%zu)", ret);
		return;
	}
	ip4 = (struct ipv4_header *)buf;

	/*
	 * Check the IPv4 header length.  Usually 20.
	 */
	skip = (ip4->ver_hlen & 0xf) * 4;
	if (skip < sizeof(*ip4)) {
		LDEBUG("raw2tun: IPv4 header too short (%zu)", skip);
		return;
	}
	if (ret < skip) {
		LDEBUG("raw2tun: IPv4 header too long (%zu < %zu)", ret, skip);
		return;
	}

	if (ret - skip < sizeof(*ip6)) {
		LDEBUG("raw2tun: no IPv6 header (%zu)", ret - skip);
		return;
	}
	ip6 = (struct ipv6_header *)(buf + skip);

	/*
	 * If the IPv6 source address is within the prefix, the embedded IPv4
	 * address should match with the outer one.  If not in the prefix,
	 * it should come from the relay router.
	 */
	if (memcmp(&c->prefix, ip6->src, c->prefixlenbyte) == 0) {
		if (memcmp(ip4->src, ip6->src + c->prefixlenbyte, 4) != 0) {
			LDEBUG("raw2tun: embedded and outer IPv4 address "
			    "mismatch (%s, %s)",
			    addr62str(ip6->src), addr42str(ip4->src));
			return;
		}
		if (reject_v4(ip6->src + c->prefixlenbyte)) {
			LDEBUG("raw2tun: reject IPv4 source (%s)",
			    addr42str(ip6->src + c->prefixlenbyte));
			return;
		}
	} else {
		/* Not true for 6to4; non-RFC-3068-anycast relays exist. */
		if (memcmp(ip4->src, &c->relay.sin_addr, 4) != 0) {
			LDEBUG("raw2tun: native address from non-relaying "
			    "router (%s, %s)",
			    addr62str(ip6->src), addr42str(ip4->src));
			return;
		}
		if (reject_v6(ip6->src)) {
			LDEBUG("raw2tun: reject IPv6 source (%s)",
			    addr62str(ip6->src));
			return;
		}
	}

	/*
	 * The IPv6 destination address should match with mine.
	 */
	if (memcmp(&c->prefix, ip6->dst, c->prefixlenbyte) != 0 ||
	    memcmp(&c->myv4, ip6->dst + c->prefixlenbyte, 4) != 0) {
		LDEBUG("raw2tun: destination is not me (%s)",
		    addr62str(ip6->dst));
		return;
	}

	/*
	 * Prepend protocol family information for TUNSIFHEAD.
	 * Space is reused from the IPv4 header.
	 */
	skip -= TUN_HEAD_LEN;
	store32(buf + skip, AF_INET6);

	if ((ret = write(c->fd_tun, buf + skip, ret - skip)) == (size_t)-1) {
		LERR("write to tun: %s", strerror(errno));
		return;
	}
	LDEBUG("%zu bytes written to tun", ret);
}

/*
 * Reject other than global unicast IPv4 addresses [RFC3056 9].
 */
static int
reject_v4(const uint8_t *addr4)
{
	uint32_t a;

	a = load32((const char *)addr4);

	if (addr4[0] == 0 || addr4[0] == 127)
		return 1;		/* self-identification, loopback */
	if ((a & 0xf0000000) == 0xe0000000)
		return 1;		/* multicast */
	if ((a & 0xff000000) == 0x0a000000 ||
	    (a & 0xfff00000) == 0xac100000 ||
	    (a & 0xffff0000) == 0xc0a80000)
		return 1;		/* private */
	if ((a & 0xffff0000) == 0xa9fe0000)
		return 1;		/* link-local */
	if (a == 0xffffffff)
		return 1;		/* limited broadcast */
	return 0;
}

/*
 * Reject non-global IPv6 addresses.  Multicast should be accepted.
 */
static int
reject_v6(const uint8_t *addr6)
{
	if (addr6[0] == 0)
		return 1;		/* compat, mapped, loopback, etc */
	if (addr6[0] == 0xff && (addr6[1] & 0x0f) != 0x0e)
		return 1;		/* multicast non-global */
	if (addr6[0] == 0xfe && (addr6[1] & 0xc0) == 0x80)
		return 1;		/* link-local unicast */
	if (addr6[0] == 0xfe && (addr6[1] & 0xc0) == 0xc0)
		return 1;		/* site-local unicast */
	return 0;
}

static const char *
addr42str(const uint8_t *addr4)
{
	static char buf[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, addr4, buf, sizeof(buf)) != NULL)
		return buf;
	else
		return "(error)";
}

static const char *
addr62str(const uint8_t *addr6)
{
	static char buf[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, addr6, buf, sizeof(buf)) != NULL)
		return buf;
	else
		return "(error)";
}


static uint32_t
load32(const char *buf)
{
	return ((uint32_t)(unsigned char)buf[0] << 24) +
	    ((uint32_t)(unsigned char)buf[1] << 16) +
	    ((uint32_t)(unsigned char)buf[2] << 8) +
	    (unsigned char)buf[3];
}

static void
store32(char *buf, uint32_t val)
{
	buf[0] = val >> 24;
	buf[1] = val >> 16;
	buf[2] = val >> 8;
	buf[3] = val;
}


#include <ctype.h>
static void
dump(const char *ptr, size_t len)
{
	char bufhex[56], *b, bufprint[17];
	const char *p;
	int i, thislen, c, used, blen;

	p = ptr;
	while (len > 0) {
		thislen = len < 16 ? len : 16;
		b = bufhex;
		blen = sizeof(bufhex);

		/* hex */
		for (i = 0; i < 16; i++) {
			used = i < thislen ?
			    snprintf(b, blen, " %02x", (unsigned char)p[i]) :
			    snprintf(b, blen, "   ");
			if (used < blen) {
				b += used;
				blen -= used;
			}
		}
		/* printable ASCII */
		for (i = 0; i < thislen; i++) {
			c = (unsigned char)p[i];
			bufprint[i] = isascii(c) && isprint(c) ? c : '.';
		}
		bufprint[i] = '\0';

		fprintf(stderr, "%p %s  %s\n", p, bufhex, bufprint);
		p += thislen;
		len -= thislen;
	}
}
