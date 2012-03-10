# $Id$

prefix=/usr/local
exec_prefix=${prefix}
sbindir=${exec_prefix}/sbin
localstatedir=/var
mandir=${prefix}/man
Dsbindir=$(DESTDIR)$(sbindir)
Dmandir=$(DESTDIR)$(mandir)

CC=cc
INSTALL=install -c
INSTALL_PROGRAM=${INSTALL}
INSTALL_DATA=${INSTALL} -m 644
CFLAGS=-O2 -g -Wall -W
CPPFLAGS=-DVAR_DIR=\"$(localstatedir)\"
LDFLAGS=
LIBOBJS=
LIBS=

PROG=u6rd
SRCS=main.c util.c
OBJS=$(SRCS:.c=.o)

all: $(PROG)

$(PROG): $(OBJS) $(LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBOBJS) $(LIBS)

.c.o:
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

install:
	$(INSTALL) -d $(Dsbindir)
	$(INSTALL_PROGRAM) $(PROG) $(Dsbindir)
	$(INSTALL) -d $(Dmandir)/man8
	$(INSTALL_DATA) u6rd.8 $(Dmandir)/man8

depend:
	mkdep -- $(CPPFLAGS) $(SRCS)
lint:
	lint $(CPPFLAGS) $(LINTFLAGS) $(SRCS)
clang-analyze:
	clang --analyze $(CPPFLAGS) $(SRCS)
clean:
	rm -f $(PROG) $(SRCS:.c=.o)
distclean: clean
	rm -f .depend
