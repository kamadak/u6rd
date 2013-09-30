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
#include <arpa/inet.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "compat/compat.h"

#include "var.h"
#include "util.h"
#include "tun_if.h"

int
open_tun(const char *devarg)
{
	struct ifreq ifr;
	int fd;

	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		LERR("open: /dev/net/tun: %s", strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN;
	if (strlcpy(ifr.ifr_name, devarg, sizeof(ifr.ifr_name)) >=
	    sizeof(ifr.ifr_name)) {
		LERR("%s: interface name too long", devarg);
		close(fd);
		return -1;
	}
	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		LERR("ioctl(TUNSETIFF): %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

size_t
check_tun_header(const char *buf, size_t len)
{
	const struct tun_pi *pi;

	if (len < sizeof(*pi)) {
		LDEBUG("tun: no address family");
		return -1;
	}
	pi = (const struct tun_pi *)buf;
	if (pi->proto != htons(ETHERTYPE_IPV6)) {
		LDEBUG("tun: non-IPv6 packet (%u)", ntohs(pi->proto));
		return -1;
	}
	return sizeof(*pi);
}

size_t
add_tun_header(char *buf, size_t space)
{
	struct tun_pi *pi;

	if (space < sizeof(*pi)) {
		LDEBUG("tun: no space for address family");
		return -1;
	}
	pi = (struct tun_pi *)(buf - sizeof(*pi));
	pi->flags = 0;
	pi->proto = htons(ETHERTYPE_IPV6);
	return sizeof(*pi);
}
