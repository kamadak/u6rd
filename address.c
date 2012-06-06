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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "util.h"
#include "address.h"

/*
 * Reject other than global unicast IPv4 addresses [RFC3056 9].
 */
int
reject_v4(const struct in_addr *addr4)
{
	const unsigned char *p;
	uint32_t a;

	p = (const unsigned char *)addr4;
	a = ntohl(addr4->s_addr);

	if (p[0] == 0 || p[0] == 127)
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
int
reject_v6(const struct in6_addr *addr6)
{
	const unsigned char *p;

	p = addr6->s6_addr;
	if (p[0] == 0)
		return 1;		/* compat, mapped, loopback, etc */
	if (p[0] == 0xff && (p[1] & 0x0f) != 0x0e)
		return 1;		/* multicast non-global */
	if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
		return 1;		/* link-local unicast */
	if (p[0] == 0xfe && (p[1] & 0xc0) == 0xc0)
		return 1;		/* site-local unicast */
	return 0;
}

int
cmp_v6prefix(const struct in6_addr *prefix,
    const struct in6_addr *addr6, int bits)
{
	const unsigned char *p1, *p2;

	p1 = prefix->s6_addr;
	p2 = addr6->s6_addr;
	for (; bits >= 8; bits -= 8)
		if (*p1++ != *p2++)
			return 1;
	if (bits == 0)
		return 0;
	return (*p1 ^ *p2) & (0xff00 >> bits);
}

void
extract_v4(struct in_addr *addr4,
    const struct in_addr *v4me, int v4commonlen,
    const struct in6_addr *addr6, int v6prefixlen)
{
	const uint32_t *p;
	uint32_t a4, a6;

	/* Common prefix. */
	a4 = ntohl(v4me->s_addr) & ~(0xffffffff >> v4commonlen);

	/* Embedded part. */
	p = (const uint32_t *)addr6;
	for (; v6prefixlen >= 32; v6prefixlen -= 32)
		p++;
	a6 = ntohl(*p) << v6prefixlen;
	if (v6prefixlen > v4commonlen)
		a6 |= ntohl(*(p + 1)) >> (32 - v6prefixlen);
	a6 >>= v4commonlen;

	addr4->s_addr = htonl(a4 | a6);
}

void
embed_v4(struct in6_addr *addr6, int v6prefixlen,
    const struct in_addr *v4me, int v4commonlen)
{
	uint32_t a4, a4mask, x;
	uint32_t *p;

	/* Discard the common prefix. */
	a4 = ntohl(v4me->s_addr) << v4commonlen;
	a4mask = 0xffffffff << v4commonlen;

	/* Embed into the IPv6 address. */
	p = (uint32_t *)addr6;
	for (; v6prefixlen >= 32; v6prefixlen -= 32)
		p++;
	x = ntohl(*p);
	x &= ~(a4mask >> v6prefixlen);
	x |= a4 >> v6prefixlen;
	*p = htonl(x);
	if (v6prefixlen > v4commonlen) {
		x = ntohl(*(p + 1));
		x &= ~(a4mask << (32 - v6prefixlen));
		x |= a4 << (32 - v6prefixlen);
		*(p + 1) = htonl(x);
	}
}

const char *
addr42str(const struct in_addr *addr4)
{
	static char buf[INET_ADDRSTRLEN];

	if (inet_ntop(AF_INET, addr4, buf, sizeof(buf)) != NULL)
		return buf;
	else
		return "(error)";
}

const char *
addr62str(const struct in6_addr *addr6)
{
	static char cyclicbuf[2][INET6_ADDRSTRLEN];
	static int idx;
	char *buf;

	buf = cyclicbuf[idx = (idx + 1) % lengthof(cyclicbuf)];
	if (inet_ntop(AF_INET6, addr6, buf, sizeof(cyclicbuf[0])) != NULL)
		return buf;
	else
		return "(error)";
}
