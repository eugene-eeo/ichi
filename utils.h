#ifndef KURV_UTILS
#define KURV_UTILS

#include <stdio.h>
#include <stdint.h>

void _free(void* buf, int bufsize);
int _fclose(FILE **fp);
int _read(FILE* fp, uint8_t *buf, size_t bufsize);
int _write(FILE* fp, const uint8_t *buf, size_t bufsize);
#endif
