CC=gcc
CFLAGS=-O3 -I. -march=native

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

kurv: kurv.o base64.o monocypher/monocypher.o
	$(CC) -o kurv \
		monocypher/monocypher.o \
		kurv.o \
		base64.o

clean:
	-rm kurv
	-rm *.o
	-rm monocypher/*.o
	-rm test

tests:
	bats test.sh
