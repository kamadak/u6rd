/* $Id$ */
/*
 * This code was written by KAMADA Ken'ichi and is in the public domain.
 */

#include <sys/types.h>

#include "compat.h"

size_t
strlcpy(char *dst, const char *src, size_t size)
{
	const char *s;

	s = src;
	if (size > 0) {
		while (*s != '\0' && --size > 0)
			*dst++ = *s++;
		*dst = '\0';
	}
	while (*s != '\0')
		s++;
	return s - src;
}
