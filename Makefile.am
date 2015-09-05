##
## Toplevel Makefile.am
##

ACLOCAL_AMFLAGS	= -I m4

SUBDIRS		= m4 test

AM_CPPFLAGS	= @GNET_CFLAGS@

sbin_PROGRAMS	= dvdnsd

dvdnsd_SOURCES	= backend.c dns.c dnsd.h main.c socket.c
dvdnsd_LDADD	= @GNET_LIBS@ @SQLITE3_LIBS@ @ARGP_LIBS@

EXTRA_DIST	= autogen.sh TODO import-zone.pl mk-dnsdb.sql BIG_FAT_WARNING
