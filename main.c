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
#include <net/if.h>
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

#include "compat/compat.h"

#include "version.h"
#include "var.h"
#include "pathnames.h"
#include "util.h"
#include "address.h"
#include "tun_if.h"

#define DEFAULT_6RD_MTU	1280
#define PACKET_BUF_SIZE	2048

struct ipv4_header {
	uint8_t ver_hlen;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t cksum;
	struct in_addr src;
	struct in_addr dst;
};

struct ipv6_header {
	uint32_t ver_class_label;
	uint16_t len;
	uint8_t next_header;
	uint8_t hop_limit;
	struct in6_addr src;
	struct in6_addr dst;
};

struct connection {
	char *buf;
	size_t size;
	struct in6_addr v6prefix;	/* 6rd prefix + embedded IPv4 addr */
	int v6prefixlen;
	struct in_addr v4me;
	int v4commonlen;
	struct sockaddr_in relay;
	int fd_tun;
	int fd_raw;
	unsigned long ipkts;
	unsigned long ierrs;
	unsigned long irjct;
	unsigned long ibytes;
	unsigned long opkts;
	unsigned long oerrs;
	unsigned long orjct;
	unsigned long obytes;
};

static void usage(void);
static void version(void);
static int parse_prefix(struct in6_addr *prefix, int *prefixlen,
    const char *prefixarg);
static int parse_len(const char *str, int min, int max, const char *name);
static int parse_relay(struct sockaddr_in *relay, const char *relayarg);
static int ifconfig(const char *devarg);
static int open_raw(struct in_addr *v4me, const char *v4mearg);
static int open_sigxfr(void);
static void sighandler(int signo);
static int set_nonblocking(int fd);
static int loop(struct connection *c);
static int read_signal(struct connection *c);
static void tun2raw(struct connection *c);
static void raw2tun(struct connection *c);

static void dump(const void *ptr, size_t len);

struct options options;

static int sigxfr[2];

int
main(int argc, char *argv[])
{
	struct connection con;
	const char *devarg, *prefixarg, *relayarg, *v4mearg;
	int c;

	setprogname(argv[0]);
	while ((c = getopt(argc, argv, "dFhr:u:V")) != -1) {
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
		case 'r':
			options.commonlen = optarg;
			break;
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
	devarg = argv[0];
	prefixarg = argv[1];
	relayarg = argv[2];
	v4mearg = argv[3];

	openlog(NULL, LOG_PERROR, LOG_DAEMON);
	if (options.debug == 0)
		setlogmask(LOG_UPTO(LOG_INFO));

	con = (struct connection){.size = PACKET_BUF_SIZE};
	if ((con.buf = (char *)malloc(con.size)) == NULL) {
		LERR("out of memory");
		exit(1);
	}

	if (parse_prefix(&con.v6prefix, &con.v6prefixlen, prefixarg) == -1)
		exit(1);
	if (parse_relay(&con.relay, relayarg) == -1)
		exit(1);

	if ((con.fd_tun = open_tun(devarg)) == -1)
		exit(1);
	if (ifconfig(devarg) == -1)
		exit(1);
	if ((con.fd_raw = open_raw(&con.v4me, v4mearg)) == -1)
		exit(1);
	if (open_sigxfr() == -1)
		exit(1);

	if (options.commonlen != NULL)
		con.v4commonlen = parse_len(options.commonlen, 0, 31,
		    "common prefix length of IPv4");
	if (con.v4commonlen == -1)
		exit(1);
	if (con.v6prefixlen + (32 - con.v4commonlen) > 64) {
		LERR("delegated prefix length is longer than 64");
		exit(1);
	}
	embed_v4(&con.v6prefix, con.v6prefixlen, &con.v4me, con.v4commonlen);

	if (!options.foreground && make_pidfile(getprogname()) == -1)
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
	printf("usage: %s [-dFhV] [-r v4_common_len] [-u user] tunN prefix/prefixlen relay_v4_addr my_v4_addr\n",
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
parse_prefix(struct in6_addr *prefix, int *prefixlen,
    const char *prefixarg)
{
	char buf[INET6_ADDRSTRLEN + 4], *p;
	int ret;

	/*
	 * Modifying strings pointed to by argv[n] is allowed in C99, but
	 * it is not a good idea, because modification to them (not limited
	 * to argv[0]) is visible to ps(1) on NetBSD.
	 */
	if (strlcpy(buf, prefixarg, sizeof(buf)) >= sizeof(buf)) {
		LERR("%s: prefix string too long", prefixarg);
		return -1;
	}

	if ((p = strchr(buf, '/')) == NULL) {
		LERR("%s: prefixlen is not specified", buf);
		return -1;
	}
	*p++ = '\0';
	ret = inet_pton(AF_INET6, buf, prefix);
	if (ret == -1) {
		LERR("%s: %s", buf, strerror(errno));
		return -1;
	} else if (ret != 1) {
		LERR("%s: failed to parse", buf);
		return -1;
	}

	/*
	 * FP + TLA uses 16 bits.  The maximum prefix length in RFC 5569
	 * is 32 [RFC5569 3], but it is said that some ISPs use longer
	 * prefixes.
	 */
	*prefixlen = parse_len(p, 16, 63, "prefixlen");
	if (*prefixlen == -1)
		return -1;
	return 0;
}

static int
parse_len(const char *str, int min, int max, const char *name)
{
	char *endptr;
	long num;

	errno = 0;
	num = strtol(str, &endptr, 10);
	if (str[0] == '\0' || *endptr != '\0') {
		LERR("%s: %s not a number", str, name);
		return -1;
	}
	if (errno == ERANGE || num < min || num > max) {
		LERR("%s: %s out of range", str, name);
		return -1;
	}
	return num;
}

static int
parse_relay(struct sockaddr_in *relay, const char *relayarg)
{
	struct addrinfo hints, *res0;
	int gairet;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_NUMERICHOST;
	gairet = getaddrinfo(relayarg, NULL, &hints, &res0);
	if (gairet != 0) {
		LERR("getaddrinfo: %s: %s", relayarg, gai_strerror(gairet));
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
ifconfig(const char *devarg)
{
	struct ifreq ifr;
	int fd;

	memset(&ifr, 0, sizeof(ifr));
	if (strlcpy(ifr.ifr_name, devarg, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name)) {
		LERR("%s: interface name too long", devarg);
		return -1;
	}

	/* Needs a dummy socket. */
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		LERR("socket: %s", strerror(errno));
		return -1;
	}
	ifr.ifr_mtu = DEFAULT_6RD_MTU;
	if (ioctl(fd, SIOCSIFMTU, &ifr) == -1) {
		LERR("ioctl(SIOCSIFMTU): %s: %s", devarg, strerror(errno));
		close(fd);
		return -1;
	}
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
		LERR("ioctl(SIOCGIFFLAGS): %s: %s", devarg, strerror(errno));
		close(fd);
		return -1;
	}
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
		LERR("ioctl(SIOCSIFFLAGS): %s: %s", devarg, strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int
open_raw(struct in_addr *v4me, const char *v4mearg)
{
	struct addrinfo hints, *res0;
	int fd, gairet, on;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	gairet = getaddrinfo(v4mearg, NULL, &hints, &res0);
	if (gairet != 0) {
		LERR("getaddrinfo: %s: %s", v4mearg, gai_strerror(gairet));
		return -1;
	}
	if (res0->ai_family != AF_INET) {
		LERR("address family mismatch");
		freeaddrinfo(res0);
		return -1;
	}
	*v4me = ((struct sockaddr_in *)res0->ai_addr)->sin_addr;

	if ((fd = socket(PF_INET, SOCK_RAW, IPPROTO_IPV6)) == -1) {
		LERR("socket: %s", strerror(errno));
		freeaddrinfo(res0);
		return -1;
	}
	on = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
		LERR("setsockopt(IP_HDRINCL): %s", strerror(errno));
		freeaddrinfo(res0);
		close(fd);
		return -1;
	}
	if (bind(fd, res0->ai_addr, res0->ai_addrlen) == -1) {
		LERR("bind: %s: %s", v4mearg, strerror(errno));
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
#ifdef SIGINFO
	(void)sigaction(SIGINFO, &sa, NULL);
#endif
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
	int maxfd, ret;

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
			if ((ret = read_signal(c)) != 0)
				return ret;
		}
	}
}

static int
read_signal(struct connection *c)
{
	int signo;

	if (read(sigxfr[0], &signo, sizeof(signo)) == -1) {
		LERR("read: %s", strerror(errno));
		return -1;
	}
	switch (signo) {
	case SIGHUP:
		break;
	case SIGTERM:
	case SIGINT:
		return 1;
#ifdef SIGINFO
	case SIGINFO:
		LINFO("Ipkts %lu, Ierrs %lu, Irjct %lu, Ibytes %lu, "
		    "Opkts %lu, Oerrs %lu, Orjct %lu, Obytes %lu",
		    c->ipkts, c->ierrs, c->irjct, c->ibytes,
		    c->opkts, c->oerrs, c->orjct, c->obytes);
		break;
#endif
	default:
		LERR("unexpected signal %d", signo);
		break;
	}
	return 0;
}

static void
tun2raw(struct connection *c)
{
	char *buf;
	struct sockaddr_in direct, *dst;
	struct ipv4_header *ip4;
	struct ipv6_header *ip6;
	const char *reason;
	size_t len, tun_hlen;

	buf = c->buf + sizeof(*ip4);
	if ((len = read(c->fd_tun, buf, c->size - sizeof(*ip4))) ==
	    (size_t)-1) {
		LERR("read: tun: %s", strerror(errno));
		goto error;
	}
	if (len == c->size - sizeof(*ip4)) {
		LDEBUG("tun2raw: packet too big");
		goto error;
	}

	if (options.debug > 1) {
		fprintf(stderr, "tun2raw:\n");
		dump(buf, len);
	}

	/*
	 * We can encapsulate only IPv6 packets.
	 */
	if ((tun_hlen = check_tun_header(buf, len)) == (size_t)-1)
		goto error;
	buf += tun_hlen;
	len -= tun_hlen;

	if (len < sizeof(*ip6)) {
		LDEBUG("tun2raw: no IPv6 header (%zu)", len);
		goto error;
	}
	ip6 = (struct ipv6_header *)buf;

	/*
	 * Check if the embedded address in the source IPv6 packet matches
	 * with my IPv4 address.  If not, the response will not reach me.
	 */
	if (cmp_v6prefix(&c->v6prefix, &ip6->src,
	    c->v6prefixlen + (32 - c->v4commonlen)) != 0) {
		reason = "source is not me";
		goto reject;
	}

	/*
	 * Check the IPv6 destination.  If the destination is within
	 * the prefix, send an encapsulated packet to the corresponding
	 * router directly.  Otherwise, send it to the relay router.
	 */
	if (cmp_v6prefix(&c->v6prefix, &ip6->dst, c->v6prefixlen) == 0) {
		/* Send to the direct peer. */
		direct = c->relay;
		extract_v4(&direct.sin_addr, &c->v4me, c->v4commonlen,
		    &ip6->dst, c->v6prefixlen);
		if (reject_v4(&direct.sin_addr)) {
			reason = "reject IPv4 destination";
			goto reject;
		}
		dst = &direct;
	} else {
		/* Send to the relay. */
		if (reject_v6(&ip6->dst)) {
			reason = "reject IPv6 destination";
			goto reject;
		}
		dst = &c->relay;
	}

	/*
	 * SO_BROADCAST is disabled by default [SUSv4, System Inferfaces,
	 * 2.10.16 Use of Options], so no need to check broadcast addresses.
	 */

	/*
	 * Copy the IPv6 Traffic Class field to the IPv4 Type of Service
	 * field [RFC5969].
	 * The ip_off and ip_len fields are in host byte order except
	 * on OpenBSD 2.1 and later (OpenBSD >= 199706) and Linux.
	 */
	ip4 = (struct ipv4_header *)(buf - sizeof(*ip4));
	ip4->ver_hlen = 4 << 4 | sizeof(*ip4) >> 2;
	ip4->tos = ntohl(ip6->ver_class_label) >> 20 & 0xff;
#if defined(__OpenBSD__) || defined(__linux__)
	ip4->len = htons(len + sizeof(*ip4));
#else
	ip4->len = len + sizeof(*ip4);
#endif
	ip4->id = 0;			/* let the kernel set */
	ip4->off = 0;
	ip4->ttl = 255;			/* MAXTTL */
	ip4->protocol = IPPROTO_IPV6;
	ip4->cksum = 0;			/* let the kernel set */
	ip4->src = c->v4me;
	ip4->dst = dst->sin_addr;

	if (sendto(c->fd_raw, buf - sizeof(*ip4), len + sizeof(*ip4), 0,
	    (struct sockaddr *)dst, sizeof(*dst)) == -1) {
		LERR("sendto: raw: %s", strerror(errno));
		goto error;
	}
	LDEBUG("out %s %s n=%u s=%zu",
	    addr62str(&ip6->src), addr62str(&ip6->dst),
	    ip6->next_header, len);
	c->opkts++;
	c->obytes += len;
	return;
reject:
	LDEBUG("tun2raw: %s (%s %s)", reason,
	    addr62str(&ip6->src), addr62str(&ip6->dst));
	c->orjct++;
	return;
error:
	c->oerrs++;
}

static void
raw2tun(struct connection *c)
{
	char *buf;
	struct in_addr addr4;
	struct ipv4_header *ip4;
	struct ipv6_header *ip6;
	const char *reason;
	size_t len, skip, tun_hlen;

	buf = c->buf;
	if ((len = recv(c->fd_raw, buf, c->size, 0)) == (size_t)-1) {
		LERR("recv: raw: %s", strerror(errno));
		goto error;
	}
	if (len == c->size) {
		LDEBUG("raw2tun: packet too big");
		goto error;
	}

	if (options.debug > 1) {
		fprintf(stderr, "raw2tun:\n");
		dump(buf, len);
	}

	if (len < sizeof(*ip4)) {
		LDEBUG("raw2tun: no IPv4 header (%zu)", len);
		goto error;
	}
	ip4 = (struct ipv4_header *)buf;

	/*
	 * Check the IPv4 header length.  Usually 20 octets.
	 */
	skip = (ip4->ver_hlen & 0xf) << 2;
	if (skip < sizeof(*ip4)) {
		LDEBUG("raw2tun: IPv4 header too short (%zu)", skip);
		goto error;
	}
	if (len < skip) {
		LDEBUG("raw2tun: IPv4 header too long (%zu, %zu)", len, skip);
		goto error;
	}
	buf += skip;
	len -= skip;

	if (len < sizeof(*ip6)) {
		LDEBUG("raw2tun: no IPv6 header (%zu)", len);
		goto error;
	}
	ip6 = (struct ipv6_header *)buf;

	/*
	 * If the IPv6 source address is within the prefix, the embedded IPv4
	 * address should match with the outer one.  If not in the prefix,
	 * it should come from the relay router.
	 */
	if (cmp_v6prefix(&c->v6prefix, &ip6->src, c->v6prefixlen) == 0) {
		extract_v4(&addr4, &c->v4me, c->v4commonlen,
		    &ip6->src, c->v6prefixlen);
		if (memcmp(&ip4->src, &addr4, 4) != 0) {
			reason = "embedded address differs from IPv4 source";
			goto reject;
		}
		if (reject_v4(&addr4)) {
			reason = "reject IPv4 source";
			goto reject;
		}
	} else {
		/* Not true for 6to4; non-RFC-3068-anycast relays exist. */
		if (memcmp(&ip4->src, &c->relay.sin_addr, 4) != 0) {
			reason = "native address from non-relaying router";
			goto reject;
		}
		if (reject_v6(&ip6->src)) {
			reason = "reject IPv6 source";
			goto reject;
		}
	}

	/*
	 * The IPv6 destination address should match with mine.
	 */
	if (cmp_v6prefix(&c->v6prefix, &ip6->dst,
	    c->v6prefixlen + (32 - c->v4commonlen)) != 0) {
		reason = "destination is not me";
		goto reject;
	}

	/*
	 * Prepend protocol family information for TUNSIFHEAD.
	 * Space is reused from the IPv4 header.
	 */
	if ((tun_hlen = add_tun_header(buf, skip)) == (size_t)-1)
		goto error;

	if (write(c->fd_tun, buf - tun_hlen, len + tun_hlen) == -1) {
		LERR("write: tun: %s", strerror(errno));
		goto error;
	}
	LDEBUG("in  %s %s %s n=%u s=%zu",
	    addr62str(&ip6->dst), addr62str(&ip6->src), addr42str(&ip4->src),
	    ip6->next_header, len);
	c->ipkts++;
	c->ibytes += len;
	return;
reject:
	LDEBUG("raw2tun: %s (%s %s %s)", reason,
	    addr62str(&ip6->dst), addr62str(&ip6->src), addr42str(&ip4->src));
	c->irjct++;
	return;
error:
	c->ierrs++;
}


#include <ctype.h>
static void
dump(const void *ptr, size_t len)
{
	char bufhex[56], *b, bufprint[17];
	const unsigned char *p;
	int i, thislen, c, used, blen;

	p = ptr;
	while (len > 0) {
		thislen = len < 16 ? len : 16;
		b = bufhex;
		blen = sizeof(bufhex);

		/* hex */
		for (i = 0; i < 16; i++) {
			used = i < thislen ?
			    snprintf(b, blen, " %02x", p[i]) :
			    snprintf(b, blen, "   ");
			if (used < blen) {
				b += used;
				blen -= used;
			}
		}
		/* printable ASCII */
		for (i = 0; i < thislen; i++) {
			c = p[i];
			bufprint[i] = isascii(c) && isprint(c) ? c : '.';
		}
		bufprint[i] = '\0';

		fprintf(stderr, "%p %s  %s\n", p, bufhex, bufprint);
		p += thislen;
		len -= thislen;
	}
}
