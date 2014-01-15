/* $Id$ */

#ifndef HAVE_GETPROGNAME
const char *getprogname(void);
void setprogname(const char *argv0);
#endif

#ifndef HAVE_STRLCPY
size_t strlcpy(char *dst, const char *src, size_t size);
#endif
