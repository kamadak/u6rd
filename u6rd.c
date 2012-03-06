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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LERR(...)	do {						\
		fprintf(stderr, __VA_ARGS__);				\
	} while (0 /* CONSTCOND */)
#define LDEBUG(...)	do {						\
		if (options.debug > 0)					\
			fprintf(stderr, __VA_ARGS__);			\
	} while (0 /* CONSTCOND */)

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
};

static void usage(void);
static int parse_prefix(struct in6_addr *prefix, int *prefixlen,
    char *prefixstr);
static int parse_myv4(struct in_addr *myv4, const char *myv4str);
static int open_tun(const char *devstr);
static int open_raw(struct sockaddr_in *relay, const char *relaystr);
static int loop(struct connection *c);
static void tun2raw(struct connection *c);
static void raw2tun(struct connection *c);
static int reject_v4(const uint8_t *addr4);
static int reject_v6(const uint8_t *addr6);
static const char *addr42str(const uint8_t *addr4);
static const char *addr62str(const uint8_t *addr6);

uint16_t load16(const char *buf);
uint32_t load32(const char *buf);
void store16(char *buf, uint16_t val);
void store32(char *buf, uint32_t val);

static void dump(const char *ptr, size_t len);

struct options options;

int
main(int argc, char *argv[])
{
	struct connection con;
	char *devstr, *prefixstr, *relaystr, *myv4str;
	int c;

	setprogname(argv[0]);

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
			options.debug++;
			break;
		default:
			usage();
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

	if (parse_prefix(&con.prefix, &con.prefixlenbyte, prefixstr) == -1)
		exit(1);
	if (parse_myv4(&con.myv4, myv4str) == -1)
		exit(1);

	if ((con.fd_tun = open_tun(devstr)) == -1)
		exit(1);
	if ((con.fd_raw = open_raw(&con.relay, relaystr)) == 1)
		exit(1);

	if (loop(&con) == -1)
		exit(1);

	exit(0);
}

static void
usage(void)
{
	printf("usage: %s [-d] /dev/tunN prefix/prefixlen relay_v4_addr my_v4_addr\n",
	    getprogname());
	exit(1);
}

static int
parse_prefix(struct in6_addr *prefix, int *prefixlenbyte, char *prefixstr)
{
	char *p;
	int prefixlen, ret;

	if ((p = strchr(prefixstr, '/')) == NULL) {
		LERR("%s: prefixlen is not specified\n", prefixstr);
		return -1;
	}
	*p++ = '\0';
	ret = inet_pton(AF_INET6, prefixstr, prefix);
	if (ret == -1) {
		LERR("%s: %s\n", prefixstr, strerror(errno));
		return -1;
	} else if (ret != 1) {
		LERR("%s: failed to parse\n", prefixstr);
		return -1;
	}
	prefixlen = atoi(p);		/* XXX overflow */
	/* FP + TLA uses 16 bits.  Not longer than 32 [RFC5569 3]. */
	if (prefixlen < 16 || prefixlen > 32) {
		LERR("prefixlen must be between 16 and 32\n");
		return -1;
	}
	if (prefixlen % 8 != 0) {
		LERR("prefixlen that is not a multiple of 8 is "
		    "not implemented\n");
		return -1;
	}
	*prefixlenbyte = prefixlen / 8;
	return 0;
}

static int
parse_myv4(struct in_addr *myv4, const char *myv4str)
{
	int ret;

	ret = inet_pton(AF_INET, myv4str, myv4);
	if (ret == -1) {
		LERR("%s: %s\n", myv4str, strerror(errno));
		return -1;
	} else if (ret != 1) {
		LERR("%s: failed to parse\n", myv4str);
		return -1;
	}
	return 0;
}

static int
open_tun(const char *devstr)
{
	int fd, on;

	on = 1;

	if ((fd = open(devstr, O_RDWR, 0)) == -1) {
		LERR("open: %s: %s\n", devstr, strerror(errno));
		return -1;
	}
	/*
	 * Requied (at least) on NetBSD to receive non-IPv4 packets.
	 * If IFHEAD is set, protocol family (4 bytes) is prepended to a
	 * packet.
	 */
	if (ioctl(fd, TUNSIFHEAD, &on) == -1) {
		LERR("ioctl(TUNSIFHEAD): %s: %s\n", devstr, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int
open_raw(struct sockaddr_in *relay, const char *relaystr)
{
	struct addrinfo hints, *res0;
	int fd, gairet;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_IPV6;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
        gairet = getaddrinfo(relaystr, NULL, &hints, &res0);
	if (gairet != 0) {
		LERR("getaddrinfo: %s: %s\n", relaystr, gai_strerror(gairet));
		return -1;
	}
	if (sizeof(*relay) != res0->ai_addrlen) {
		LERR("length of sockaddr_in mismatch\n");
		freeaddrinfo(res0);
		return -1;
	}
	memcpy(relay, res0->ai_addr, sizeof(*relay));
	freeaddrinfo(res0);

	if ((fd = socket(PF_INET, SOCK_RAW, IPPROTO_IPV6)) == -1) {
		LERR("socket: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

static int
loop(struct connection *c)
{
	fd_set rfds, rfds0;
	int maxfd, ret;

	FD_ZERO(&rfds0);
	FD_SET(c->fd_tun, &rfds0);
	FD_SET(c->fd_raw, &rfds0);
	maxfd = c->fd_tun > c->fd_raw ? c->fd_tun : c->fd_raw;

	for (;;) {
		rfds = rfds0;
		ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			LERR("select: %s\n", strerror(errno));
			return -1;
		}
		if (FD_ISSET(c->fd_tun, &rfds))
			tun2raw(c);
		if (FD_ISSET(c->fd_raw, &rfds))
			raw2tun(c);
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
		LERR("read from tun: %s\n", strerror(errno));
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
	if (ret < 4) {
		LDEBUG("tun2raw: no address family\n");
		return;
	}
	if ((family = load32(buf)) != AF_INET6) {
		LDEBUG("tun2raw: non-IPv6 packet (%lu)\n", family);
		return;
	}

	if (ret - 4 < sizeof(*ip6)) {
		LDEBUG("tun2raw: no IPv6 header (%zu)\n", ret - 4);
		return;
	}
	ip6 = (struct ipv6_header *)(buf + 4);

	/*
	 * Check if the embedded address in the source IPv6 packet matches
	 * with my IPv4 address.  If not, the response will not reach me.
	 */
	if (memcmp(&c->prefix, ip6->src, c->prefixlenbyte) != 0 ||
	    memcmp(&c->myv4, ip6->src + c->prefixlenbyte, 4) != 0) {
		LDEBUG("tun2raw: source is not me (%s)\n",
		    addr62str(ip6->src));
		return;
	}

	/*
	 * Check the IPv6 destination.  If the destination is within
	 * the prefix, send an encapsulated packet to the corresponding
	 * router directly.  Otherwise, send it to the relay router.
	 */
	if (memcmp(&c->prefix, ip6->dst, c->prefixlenbyte) == 0) {
		if (reject_v4(ip6->dst + c->prefixlenbyte)) {
			LDEBUG("tun2raw: reject IPv4 destination (%s)\n",
			    addr42str(ip6->dst + c->prefixlenbyte));
			return;
		}
		/* Send to the direct peer. */
		direct = c->relay;
		memcpy(&direct.sin_addr, ip6->dst + c->prefixlenbyte, 4);
		dst = &direct;
	} else {
		if (reject_v6(ip6->dst)) {
			LDEBUG("tun2raw: reject IPv6 destination (%s)\n",
			    addr62str(ip6->dst));
			return;
		}
		/* Send to the relay. */
		dst = &c->relay;
	}

	if ((ret = sendto(c->fd_raw, buf + 4, ret - 4, 0,
	    (struct sockaddr *)dst, sizeof(*dst))) == (size_t)-1) {
		LERR("write to raw: %s\n", strerror(errno));
		return;
	}
	LDEBUG("%zu bytes written to raw\n", ret);
}

static void
raw2tun(struct connection *c)
{
	char buf[2048];
	struct ipv4_header *ip4;
	struct ipv6_header *ip6;
	size_t skip, ret;

	if ((ret = recv(c->fd_raw, buf, sizeof(buf), 0)) == (size_t)-1) {
		LERR("read from raw: %s\n", strerror(errno));
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
		LDEBUG("raw2tun: no IPv4 header (%zu)\n", ret);
		return;
	}
	ip4 = (struct ipv4_header *)buf;

	/*
	 * Check the IPv4 header length.  Usually 20.
	 */
	skip = (ip4->ver_hlen & 0xf) * 4;
	if (skip < sizeof(*ip4)) {
		LDEBUG("raw2tun: IPv4 header too short (%zu)\n", skip);
		return;
	}
	if (ret < skip) {
		LDEBUG("raw2tun: IPv4 header too long (%zu < %zu)\n",
		    ret, skip);
		return;
	}

	if (ret - skip < sizeof(*ip6)) {
		LDEBUG("raw2tun: no IPv6 header (%zu)\n", ret - skip);
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
			    "mismatch (%s, %s)\n",
			    addr62str(ip6->src), addr42str(ip4->src));
			return;
		}
		if (reject_v4(ip6->src + c->prefixlenbyte)) {
			LDEBUG("raw2tun: reject IPv4 source (%s)\n",
			    addr42str(ip6->src + c->prefixlenbyte));
			return;
		}
	} else {
		/* Not true for 6to4; non-RFC-3068-anycast relays exist. */
		if (memcmp(ip4->src, &c->relay.sin_addr, 4) != 0) {
			LDEBUG("raw2tun: native address from non-relaying "
			    "router (%s, %s)\n",
			    addr62str(ip6->src), addr42str(ip4->src));
			return;
		}
		if (reject_v6(ip6->src)) {
			LDEBUG("raw2tun: reject IPv6 source (%s)\n",
			    addr62str(ip6->src));
			return;
		}
	}

	/*
	 * The IPv6 destination address should match with mine.
	 */
	if (memcmp(&c->prefix, ip6->dst, c->prefixlenbyte) != 0 ||
	    memcmp(&c->myv4, ip6->dst + c->prefixlenbyte, 4) != 0) {
		LDEBUG("raw2tun: destination is not me (%s)\n",
		    addr62str(ip6->dst));
		return;
	}

	/*
	 * Prepend protocol family information for TUNSIFHEAD.
	 * Space is reused from the IPv4 header.
	 */
	skip -= 4;
	store32(buf + skip, AF_INET6);

	if ((ret = write(c->fd_tun, buf + skip, ret - skip)) == (size_t)-1) {
		LERR("write to tun: %s\n", strerror(errno));
		return;
	}
	LDEBUG("%zu bytes written to tun\n", ret);
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


uint16_t
load16(const char *buf)
{
	return ((uint16_t)(unsigned char)buf[0] << 8) + (unsigned char)buf[1];
}

uint32_t
load32(const char *buf)
{
	return ((uint32_t)(unsigned char)buf[0] << 24) +
	    ((uint32_t)(unsigned char)buf[1] << 16) +
	    ((uint32_t)(unsigned char)buf[2] << 8) +
	    (unsigned char)buf[3];
}

void
store16(char *buf, uint16_t val)
{
	buf[0] = val >> 8;
	buf[1] = val;
}

void
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
