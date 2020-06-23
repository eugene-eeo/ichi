ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif
CC=gcc
CFLAGS=-Wall -O3 -I. -march=native

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64.o monocypher/monocypher.o
	$(CC) -o kurv $^

clean:
	-rm kurv
	-rm *.o
	-rm monocypher/*.o
	-rm -rf test

tests: kurv
	bats test.sh

all: clean kurv tests

install: kurv
	install -d $(DESTDIR)$(PREFIX)/bin/
	install ./kurv $(DESTDIR)$(PREFIX)/bin/kurv

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/kurv
