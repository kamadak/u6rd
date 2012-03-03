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

static void usage(void);
static int read_prefix(struct in6_addr *prefix, int *prefixlen,
    char *prefixstr);
static int open_tun(const char *devstr);
static int open_raw(const char *relaystr, struct sockaddr_in *relay);
static int loop(int fd_tun, int fd_raw,
    struct in6_addr *prefix, int prefixlenbyte, struct sockaddr_in *relay);
static void tun2raw(int fd_tun, int fd_raw,
    struct in6_addr *prefix, int prefixlenbyte, struct sockaddr_in *relay);
static void raw2tun(int fd_tun, int fd_raw);

uint16_t load16(const char *buf);
uint32_t load32(const char *buf);
void store16(char *buf, uint16_t val);
void store32(char *buf, uint32_t val);

static void dump(const char *ptr, size_t len);

int
main(int argc, char *argv[])
{
	char *devstr, *prefixstr, *relaystr, *localstr;
	struct in6_addr prefix;
	struct sockaddr_in relay;
	int prefixlen, fd_tun, fd_raw;
	int c;

	setprogname(argv[0]);

	while ((c = getopt(argc, argv, "d")) != -1) {
		switch (c) {
		case 'd':
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
	localstr = argv[3];

	if (read_prefix(&prefix, &prefixlen, prefixstr) == -1)
		exit(1);

	if ((fd_tun = open_tun(devstr)) == -1)
		exit(1);
	if ((fd_raw = open_raw(relaystr, &relay)) == 1)
		exit(1);

	if (loop(fd_tun, fd_raw, &prefix, prefixlen / 8, &relay) == -1)
		exit(1);

	exit(0);
}

static void
usage(void)
{
	printf("usage: %s /dev/tunN prefix/prefixlen relay_v4_addr local_v4_addr\n",
	    getprogname());
	exit(1);
}

static int
read_prefix(struct in6_addr *prefix, int *prefixlen, char *prefixstr)
{
	char *p;
	int ret;

	if ((p = strchr(prefixstr, '/')) == NULL) {
		fprintf(stderr, "%s: prefixlen is not specified\n", prefixstr);
		return -1;
	}
	*p++ = '\0';
	ret = inet_pton(AF_INET6, prefixstr, prefix);
	if (ret == -1) {
		fprintf(stderr, "%s: %s\n", prefixstr, strerror(errno));
		return -1;
	} else if (ret != 1) {
		fprintf(stderr, "%s: failed to parse\n", prefixstr);
		return -1;
	}
	*prefixlen = atoi(p);		/* XXX overflow */
	/* FP + TLA uses 16 bits.  Not longer than 32 [RFC5569 3]. */
	if (*prefixlen < 16 || *prefixlen > 32) {
		fprintf(stderr, "prefixlen must be between 16 and 32\n");
		return -1;
	}
	if (*prefixlen % 8 != 0) {
		fprintf(stderr, "prefixlen that is not a multiple of 8 is "
		    "not implemented\n");
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
		fprintf(stderr, "open: %s: %s\n", devstr, strerror(errno));
		return -1;
	}
	/*
	 * Requied (at least) on NetBSD to receive non-IPv4 packets.
	 * If IFHEAD is set, protocol family (4 bytes) is prepended to a
	 * packet.
	 */
	if (ioctl(fd, TUNSIFHEAD, &on) == -1) {
		fprintf(stderr, "ioctl(TUNSIFHEAD): %s: %s\n",
		    devstr, strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

static int
open_raw(const char *relaystr, struct sockaddr_in *relay)
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
		fprintf(stderr, "getaddrinfo: %s: %s\n",
		    relaystr, gai_strerror(gairet));
		return -1;
	}
	if (sizeof(*relay) != res0->ai_addrlen) {
		fprintf(stderr, "length of sockaddr_in mismatch\n");
		freeaddrinfo(res0);
		return -1;
	}
	memcpy(relay, res0->ai_addr, sizeof(*relay));
	freeaddrinfo(res0);

	if ((fd = socket(PF_INET, SOCK_RAW, IPPROTO_IPV6)) == -1) {
		fprintf(stderr, "socket: %s\n", strerror(errno));
		return -1;
	}

	return fd;
}

static int
loop(int fd_tun, int fd_raw,
    struct in6_addr *prefix, int prefixlenbyte, struct sockaddr_in *relay)
{
	fd_set rfds, rfds0;
	int maxfd, ret;

	FD_ZERO(&rfds0);
	FD_SET(fd_tun, &rfds0);
	FD_SET(fd_raw, &rfds0);
	maxfd = fd_tun > fd_raw ? fd_tun : fd_raw;

	for (;;) {
		rfds = rfds0;
		ret = select(maxfd + 1, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			fprintf(stderr, "select: %s\n", strerror(errno));
			return -1;
		}
		if (FD_ISSET(fd_tun, &rfds))
			tun2raw(fd_tun, fd_raw, prefix, prefixlenbyte, relay);
		if (FD_ISSET(fd_raw, &rfds))
			raw2tun(fd_tun, fd_raw);
	}
	/* NOTREACHED */
	return 0;
}

static void
tun2raw(int fd_tun, int fd_raw,
    struct in6_addr *prefix, int prefixlenbyte, struct sockaddr_in *relay)
{
	char buf[2048];
	struct sockaddr_in direct, *dst;
	struct ipv6_header *ip6;
	uint32_t family;
	size_t ret;

	if ((ret = read(fd_tun, buf, sizeof(buf))) == (size_t)-1) {
		fprintf(stderr, "read from tun: %s\n", strerror(errno));
		return;
	}
	if (ret == sizeof(buf)) {
		fprintf(stderr, "tun2raw: packet too big");
		return;
	}

	fprintf(stderr, "tun2raw:\n");
	dump(buf, ret);

	/*
	 * We can encapsulate only IPv6 packets.
	 */
	if (ret < 4) {
		fprintf(stderr, "tun2raw: no address family\n");
		return;
	}
	if ((family = load32(buf)) != AF_INET6) {
		fprintf(stderr, "tun2raw: non-IPv6 packet (%lu)\n",
		    (unsigned long)family);
		return;
	}
	/* XXX and inspect the version in the packet? */

	/* XXX check addresses; src is mine? */

	/*
	 * Check the IPv6 destination.
	 * If the destination is within the prefix, send an encapsulated
	 * packet to the router directly.
	 */
	if (ret - 4 < sizeof(*ip6)) {
		fprintf(stderr, "tun2raw: no IPv6 header (%zu)\n", ret);
		return;
	}
	ip6 = (struct ipv6_header *)(buf + 4);
	if (memcmp(prefix, ip6->dst, prefixlenbyte) == 0) {
		/* get peer's IPv4 address */
		direct = *relay;
		memcpy(&direct.sin_addr, &ip6->dst[prefixlenbyte], 4);
		dst = &direct;
	} else
		dst = relay;

	/* XXX what to do if the size is larger than MTU? */

	if ((ret = sendto(fd_raw, buf + 4, ret - 4, 0,
	    (struct sockaddr *)dst, sizeof(*dst))) == (size_t)-1) {
		fprintf(stderr, "write to raw: %s\n", strerror(errno));
		return;
	}
	fprintf(stderr, "%zu bytes written to raw\n", ret);
}

static void
raw2tun(int fd_tun, int fd_raw)
{
	char buf[2048];
	struct ipv4_header *ip4;
	size_t skip, ret;

	if ((ret = recv(fd_raw, buf, sizeof(buf), 0)) == (size_t)-1) {
		fprintf(stderr, "read from raw: %s\n", strerror(errno));
		return;
	}
	if (ret == sizeof(buf)) {
		fprintf(stderr, "raw2tun: packet too big");
		return;
	}

	fprintf(stderr, "raw2tun:\n");
	dump(buf, ret);

	/* XXX check ipv4? */

	if (ret < sizeof(*ip4)) {
		fprintf(stderr, "raw2tun: no IPv4 header (%zu)\n", ret);
		return;
	}
	ip4 = (struct ipv4_header *)buf;
	skip = (ip4->ver_hlen & 0xf) * 4;
	if (skip < sizeof(*ip4)) {
		fprintf(stderr,
		    "raw2tun: IPv4 header too short (%zu)\n", skip);
		return;
	}
	if (ret < skip) {
		fprintf(stderr,
		    "raw2tun: IPv4 header too long (%zu < %zu)\n", ret, skip);
		return;
	}

	/* XXX check if IPv6 */
	/* XXX check addresses; ip4 ip6 match?
	   dest is mine? */

	/*
	 * Prepend protocol family information for TUNSIFHEAD.
	 * Space is reused from the IPv4 header.
	 */
	skip -= 4;
	store32(buf + skip, AF_INET6);

	if ((ret = write(fd_tun, buf + skip, ret - skip)) == (size_t)-1) {
		fprintf(stderr, "write to tun: %s\n", strerror(errno));
		return;
	}
	fprintf(stderr, "%zu bytes written to tun\n", ret);
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

		printf("%p %s  %s\n", p, bufhex, bufprint);
		p += thislen;
		len -= thislen;
	}
}
