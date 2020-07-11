#ifndef KURV_UTILS
#define KURV_UTILS

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define _err(name, ...) {\
    fprintf(stderr, "%s: ", name);\
    fprintf(stderr, __VA_ARGS__);\
    if (errno) {\
        fprintf(stderr, ": ");\
        perror(NULL);\
    }\
    else fprintf(stderr, "\n");\
}

void _free(void* buf, int bufsize);
int _fclose(FILE **fp);
int _read(FILE* fp, uint8_t *buf, size_t bufsize);
int _write(FILE* fp, const uint8_t *buf, size_t bufsize);
int _random(uint8_t *buf, size_t bufsize);
#endif
