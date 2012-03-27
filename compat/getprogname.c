/* $Id$ */
/*
 * This code was written by KAMADA Ken'ichi, and in the public domain.
 */

#include <stdlib.h>
#include <string.h>

#include "compat.h"

static const char *myname = NULL;

const char *
getprogname(void)
{
	return myname;
}

void
setprogname(const char *argv0)
{
	const char *p;

	if (argv0 != NULL) {
		if ((p = strrchr(argv0, '/')) != NULL)
			myname = p + 1;
		else
			myname = argv0;
	} else
		myname = NULL;
}
