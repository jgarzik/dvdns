
CC=gcc

INCLUDES=-I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include \
	-I/usr/include/gnet-2.0 -I/usr/lib64/gnet-2.0/include
OPT=-O -g
CFLAGS=$(INCLUDES) $(OPT) -Wall

LD=gcc
LDFLAGS=$(OPT)
LIBS=-lsqlite3 -lgnet-2.0 -lglib-2.0

OBJS=backend.o dns.o main.o socket.o


default::	all

distclean::	clean

all::		dnsd dns.db

dnsd:		$(OBJS)
	$(LD) $(LDFLAGS) -o dnsd $(OBJS) $(LIBS)
dns.db:		dnsdb-data.sql  mk-dnsdb.sql
	rm -f dns.db
	sqlite3 dns.db < mk-dnsdb.sql
	sqlite3 dns.db < dnsdb-data.sql

clean:
	rm -f dns.db dnsd $(OBJS)

backend.o:	dnsd.h backend.c
dns.o:		dnsd.h dns.c
main.o:		dnsd.h main.c
socket.o:	dnsd.h socket.c
