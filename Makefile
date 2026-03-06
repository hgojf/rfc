.PHONY: all install

PREFIX ?= /usr/local

all: rfc.out rfctags

rfc.out: rfc
	sed 's|$${PREFIX}|${PREFIX}|g' < rfc > rfc.out

rfctags: rfctags.o
	$(CC) -o $@ $(LDFLAGS) rfctags.o

install:
	$(INSTALL) -m 0755 rfc.out ${PREFIX}/bin/rfc
	$(INSTALL) -m 0755 rfctags ${PREFIX}/libexec
