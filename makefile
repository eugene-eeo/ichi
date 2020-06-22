kurv: kurv.c base64.c
	gcc monocypher/monocypher.c base64.c kurv.c -O3 -march=native -o kurv

clean:
	rm kurv
