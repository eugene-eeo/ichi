ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif
CC=gcc
CFLAGS=-Wall -O3 -march=native

all: kurv luck

full: clean all tests

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64/base64.o monocypher/monocypher.o
	$(CC) -o kurv $^

luck: luck.o monocypher/monocypher.o
	$(CC) -o luck $^

clean:
	-rm kurv luck
	-rm *.o
	-rm monocypher/*.o
	-rm -rf test

tests: kurv luck
	bats test_kurv.sh
	bats test_luck.sh

install: kurv
	install -d $(DESTDIR)$(PREFIX)/bin/
	install ./kurv $(DESTDIR)$(PREFIX)/bin/kurv

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/kurv
