ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif
CC=gcc
CFLAGS=-Wall -O3 -march=native

all: kurv luck

full: clean all tests

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64/base64.o monocypher/monocypher.o utils.o
	$(CC) -o kurv $^

luck: luck.o monocypher/monocypher.o utils.o
	$(CC) -o luck $^

b64: b64.o utils.o monocypher/monocypher.o base64/base64.o
	$(CC) -o b64 $^

clean:
	-rm kurv luck b64
	-rm *.o */*.o
	-rm -rf test

tests: kurv luck
	bats test_kurv.sh
	bats test_luck.sh

install: kurv luck
	install -d $(DESTDIR)$(PREFIX)/bin/
	install ./kurv $(DESTDIR)$(PREFIX)/bin/kurv
	install ./luck $(DESTDIR)$(PREFIX)/bin/luck

uninstall:
	rm $(DESTDIR)$(PREFIX)/bin/kurv
	rm $(DESTDIR)$(PREFIX)/bin/luck
