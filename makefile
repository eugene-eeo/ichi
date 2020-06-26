ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif
CC=gcc
CFLAGS=-Wall -O3 -march=native

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64/base64.o monocypher/monocypher.o
	$(CC) -o kurv $^

luck: luck.o base64/base64.o monocypher/monocypher.o
	$(CC) -o luck $^

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
