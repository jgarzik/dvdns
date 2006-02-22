
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

all::		dnsd

dnsd:		$(OBJS)
	$(LD) $(LDFLAGS) -o dnsd $(OBJS) $(LIBS)

clean:
	rm -f dnsd $(OBJS)

