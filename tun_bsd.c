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
#include <net/if_tun.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "pathnames.h"
#include "util.h"
#include "tun_if.h"

int
open_tun(const char *devarg)
{
	char devpath[32];
	size_t len;
	int fd, on;

	on = 1;

	len = snprintf(devpath, sizeof(devpath), "%s/%s", DEV_DIR, devarg);
	if (len >= sizeof(devpath)) {
		LERR("%s: device pathname too long", devarg);
		return -1;
	}
	if ((fd = open(devpath, O_RDWR, 0)) == -1) {
		LERR("open: %s: %s", devpath, strerror(errno));
		return -1;
	}
#if !defined(__OpenBSD__)
	/*
	 * Requied to receive non-IPv4 packets on FreeBSD and NetBSD.
	 * If IFHEAD is set, protocol family (4 bytes) is prepended
	 * to each packet.  OpenBSD does the same thing from the beginning,
	 * so there is no flag.
	 */
	if (ioctl(fd, TUNSIFHEAD, &on) == -1) {
		LERR("ioctl(TUNSIFHEAD): %s: %s", devpath, strerror(errno));
		close(fd);
		return -1;
	}
#endif
	return fd;
}
