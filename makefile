CC=gcc
CFLAGS=-Wall -O3 -I. -march=native

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64.o monocypher/monocypher.o
	$(CC) -o kurv \
		monocypher/monocypher.o \
		kurv.o \
		base64.o

debug:
	$(CC) -o kurv \
		monocypher/monocypher.c \
		kurv.c \
		base64.c \
		-Og -g

clean:
	-rm kurv
	-rm *.o
	-rm monocypher/*.o
	-rm -rf test

tests: kurv
	bats test.sh

all: clean kurv tests
