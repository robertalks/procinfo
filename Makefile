ifndef CC
CC = cc
endif

ifndef CFLAGS
CFLAGS = -Wall -O0 -g -Wformat-truncation=0
endif

ifndef DESTDIR
DESTDIR = /usr/local
endif

all: procinfo

clean:
	rm -vf *.o
	rm -vf procinfo

install:
	/usr/bin/strip -v --strip-unneeded procinfo
	install -v -m 0755 procinfo $(DESTDIR)/bin/procinfo

uninstall:
	[ -x $(DESTDIR)/bin/procinfo ] && rm -vf $(DESTDIR)/bin/procinfo

procinfo: procinfo.o
	$(CC) $(CFLAGS) -o $@ $^
