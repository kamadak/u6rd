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
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <arpa/inet.h>
#include <net/if_utun.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "var.h"
#include "util.h"
#include "tun_if.h"

#define TUN_HEAD_LEN	4		/* TUNSIFHEAD */

int
open_tun(const char *devarg)
{
	struct sockaddr_ctl sc;
	struct ctl_info ci;
	unsigned int unit_num;
	int fd;

	/* XXX overflow */
	if (sscanf(devarg, "utun%u", &unit_num) != 1) {
		LERR("%s: invalid utun device name", devarg);
		return -1;
	}

	memset(&ci, 0, sizeof(ci));
	if (strlcpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name)) >=
	    sizeof(ci.ctl_name)) {
		LERR("UTUN_CONTROL_NAME too long");
		return -1;
	}
	if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1) {
		LERR("socket(SYSPROTO_CONTROL): %s", strerror(errno));
		return -1;
	}
	if (ioctl(fd, CTLIOCGINFO, &ci) == -1) {
		LERR("ioctl(CTLIOCGINFO): %s", strerror(errno));
		close(fd);
		return -1;
	}
	memset(&sc, 0, sizeof(sc)));
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id = ci.ctl_id;
	sc.sc_unit = unit_num + 1;		/* zero means unspecified */
	if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) == -1) {
		LERR("connect(AF_SYS_CONTROL): %s", strerror(errno));
		close(fd);
		return -1;
	}
	return fd;
}

size_t
check_tun_header(const char *buf, size_t len)
{
	unsigned long family;

	if (len < TUN_HEAD_LEN) {
		LDEBUG("tun: no address family");
		return -1;
	}
	if ((family = ntohl(*(const uint32_t *)buf)) != AF_INET6) {
		LDEBUG("tun: non-IPv6 packet (%lu)", family);
		return -1;
	}
	return TUN_HEAD_LEN;
}

size_t
add_tun_header(char *buf, size_t space)
{
	if (space < TUN_HEAD_LEN) {
		LDEBUG("tun: no space for address family");
		return -1;
	}
	*(uint32_t *)(buf - TUN_HEAD_LEN) = htonl(AF_INET6);
	return TUN_HEAD_LEN;
}
