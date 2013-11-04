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

#include "pathnames.h"
#include "util.h"

static void lose_pidfile(struct pidfile *pf);

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

struct pidfile *
make_pidfile(const char *myname)
{
	struct pidfile *pf;
	size_t dirlen, pathlen;

	dirlen = strlen(PIDFILE_DIR);
	pathlen = dirlen + 1 + strlen(myname) + 4 + 1;
	if ((pf = (struct pidfile *)malloc(sizeof(*pf) + pathlen)) == NULL) {
		LERR("out of memory");
		return NULL;
	}
	pf->fd = -1;
	pf->dirfd = -1;
	snprintf(pf->path, pathlen, "%s/%s.pid", PIDFILE_DIR, myname);
	pf->name = pf->path + dirlen + 1;

#if defined(ENABLE_CAPSICUM)
	if ((pf->dirfd = open(PIDFILE_DIR, O_DIRECTORY)) == -1) {
		LERR("open: %s: %s", PIDFILE_DIR, strerror(errno));
		lose_pidfile(pf);
		return NULL;
	}
#endif

	/*
	 * On BSD systems, use flock(2); otherwise, use fcntl(2).
	 * The fcntl locks are not inherited by a child process, so
	 * fcntl locking is done in write_pidfile().
	 */
#ifdef O_EXLOCK
# define OPEN_FLAGS (O_WRONLY | O_CREAT | O_EXLOCK | O_NONBLOCK)
#else
# define OPEN_FLAGS (O_WRONLY | O_CREAT)
#endif
	if ((pf->fd = open(pf->path, OPEN_FLAGS, 0644)) == -1) {
		LERR("%s: open: %s", pf->path, strerror(errno));
		lose_pidfile(pf);
		return NULL;
	}
#undef OPEN_MODE

	return pf;
}

int
write_pidfile(struct pidfile *pf)
{
	char pidstr[16];
	pid_t pid;

#ifndef O_EXLOCK
	/* .l_start and .l_len are 0 to lock the entire file. */
	if (fcntl(pf->fd, F_SETLK,
	    &(struct flock) { .l_whence = SEEK_SET, .l_type = F_WRLCK }
	    ) == -1) {
		LERR("%s: fcntl(F_SETLK): %s", pf->path, strerror(errno));
		pf->name = NULL;	/* mark to call lose_pidfile() */
		return -1;
	}
#endif

	if (ftruncate(pf->fd, 0) == -1) {
		LERR("%s: ftruncate: %s", pf->path, strerror(errno));
		return -1;
	}
	pid = getpid();
	snprintf(pidstr, sizeof(pidstr), "%d\n", (int)pid);
	if (write(pf->fd, pidstr, strlen(pidstr)) == -1) {
		LERR("%s: write: %s", pf->path, strerror(errno));
		return -1;
	}
	return 0;
}

void
cleanup_pidfile(struct pidfile *pf)
{
	struct stat sb1, sb2;

	if (pf == NULL)
		return;
	if (pf->name == NULL) {
		lose_pidfile(pf);
		return;
	}

	/* NB: race between stat() and unlink() */
	if (fstat(pf->fd, &sb1) == -1)
		LERR("fstat PID file failed: %s", strerror(errno));
#if defined(ENABLE_CAPSICUM)
	else if (fstatat(pf->dirfd, pf->name, &sb2, 0) == -1)
		LERR("%s: fstatat: %s", pf->path, strerror(errno));
#else
	else if (stat(pf->path, &sb2) == -1)
		LERR("%s: stat: %s", pf->path, strerror(errno));
#endif
	else if (sb1.st_dev != sb2.st_dev || sb1.st_ino != sb2.st_ino)
		LERR("PID file is replaced; exiting without unlinking it");
	else {
		/* If root priv has been dropped, unlink will fail. */
#if defined(ENABLE_CAPSICUM)
		if (unlinkat(pf->dirfd, pf->name, 0) == -1 &&
		    ftruncate(pf->fd, 0) == -1)
			LERR("%s: ftruncate: %s", pf->path, strerror(errno));
#else
		if (unlink(pf->path) == -1 &&
		    ftruncate(pf->fd, 0) == -1)
			LERR("%s: ftruncate: %s", pf->path, strerror(errno));
#endif
	}

	close(pf->fd);
	if (pf->dirfd != -1)
		close(pf->dirfd);
	free(pf);
}

/* Unlike cleanup_pidfile(), this will never unlink the file. */
static void
lose_pidfile(struct pidfile *pf)
{
	if (pf->fd != -1)
		close(pf->fd);
	if (pf->dirfd != -1)
		close(pf->dirfd);
	free(pf);
}
