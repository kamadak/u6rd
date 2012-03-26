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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "compat/compat.h"

#include "pathnames.h"
#include "util.h"

static void lose_pidfile(void);

static char *pidfile = NULL;
static int pidfile_fd = -1;

int
run_as(const char *user)
{
	struct passwd *pw;

	if ((pw = getpwnam(user)) == NULL) {
		LERR("%s: user not found", user);
		return -1;
	}
	if (setgid(pw->pw_gid) == -1) {
		LERR("setgid: %s", strerror(errno));
		return -1;
	}
	if (setgroups(1, &pw->pw_gid) == -1) {
		LERR("setgroups: %s", strerror(errno));
		return -1;
	}
	if (setuid(pw->pw_uid) == -1) {
		LERR("setuid: %s", strerror(errno));
		return -1;
	}
	return 0;
}

int
make_pidfile(void)
{
	const char *myname;
	size_t len;

	if (pidfile != NULL || pidfile_fd != -1) {
		LERR("make_pidfile() is called twice");
		return -1;
	}

	myname = getprogname();
	len = strlen(PIDFILE_DIR) + 1 + strlen(myname) + 4 + 1;
	if ((pidfile = (char *)malloc(len)) == NULL) {
		LERR("out of memory");
		return -1;
	}
	snprintf(pidfile, len, "%s/%s.pid", PIDFILE_DIR, myname);

	/*
	 * On BSD systems, use flock(2); otherwise, use fcntl(2).
	 * The fcntl locks are not inherited by a child process, so
	 * fcntl locking is done in write_pidfile().
	 */
#ifdef O_EXLOCK
	if ((pidfile_fd = open(pidfile,
	    O_WRONLY | O_CREAT | O_EXLOCK | O_NONBLOCK, 0644)) == -1) {
		LERR("%s: open: %s", pidfile, strerror(errno));
		lose_pidfile();
		return -1;
	}
#else
	if ((pidfile_fd = open(pidfile, O_WRONLY | O_CREAT, 0644)) == -1) {
		LERR("%s: open: %s", pidfile, strerror(errno));
		lose_pidfile();
		return -1;
	}
#endif

	return 0;
}

int
write_pidfile(void)
{
	char pidstr[16];
	pid_t pid;

#ifndef O_EXLOCK
	/* .l_start and .l_len are 0 to lock the entire file. */
	if (fcntl(pidfile_fd, F_SETLK,
	    &(struct flock) { .l_whence = SEEK_SET, .l_type = F_WRLCK }
	    ) == -1) {
		LERR("%s: fcntl(F_SETLK): %s", pidfile, strerror(errno));
		lose_pidfile();
		return -1;
	}
#endif

	if (ftruncate(pidfile_fd, 0) == -1) {
		LERR("%s: ftruncate: %s", pidfile, strerror(errno));
		return -1;
	}
	pid = getpid();
	snprintf(pidstr, sizeof(pidstr), "%d\n", (int)pid);
	if (write(pidfile_fd, pidstr, strlen(pidstr)) == -1) {
		LERR("%s: write: %s", pidfile, strerror(errno));
		return -1;
	}
	return 0;
}

void
cleanup_pidfile(void)
{
	struct stat sb1, sb2;

	if (pidfile == NULL && pidfile_fd == -1)
		return;
	if (pidfile == NULL || pidfile_fd == -1) {
		LERR("inconsistent PID file info");
		return;
	}

	/* NB: race between stat() and unlink() */
	if (fstat(pidfile_fd, &sb1) == -1)
		LERR("fstat PID file failed: %s", strerror(errno));
	else if (stat(pidfile, &sb2) == -1)
		LERR("%s: stat: %s", pidfile, strerror(errno));
	else if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
		LERR("PID file is replaced; exiting without unlinking it");
	else {
		/* If root priv has been dropped, unlink will fail. */
		if (unlink(pidfile) == -1 &&
		    ftruncate(pidfile_fd, 0) == -1)
			LERR("%s: ftruncate: %s", pidfile, strerror(errno));
	}

	free(pidfile);
	pidfile = NULL;
	close(pidfile_fd);
	pidfile_fd = -1;
}

/* Unlike cleanup_pidfile(), this will never unlink the file. */
static void
lose_pidfile(void)
{
	if (pidfile_fd != -1)
		close(pidfile_fd);
	pidfile_fd = -1;
	free(pidfile);
	pidfile = NULL;
}
