#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>
#include <errno.h>
#include "monocypher/monocypher.h"

void _free(void* buf, int bufsize)
{
    if (buf != NULL) {
        crypto_wipe(buf, bufsize);
        free(buf);
    }
}

int _fclose(FILE **fp)
{
    int rv = fclose(*fp);
    *fp = NULL;
    return rv;
}

int _read(FILE* fp, uint8_t *buf, size_t bufsize)
{
    return fread(buf, 1, bufsize, fp) == bufsize ? 0 : -1;
}

int _write(FILE* fp, const uint8_t *buf, size_t bufsize)
{
    return (fwrite(buf, 1, bufsize, fp) == bufsize && errno == 0) ? 0 : -1;
}

int _random(uint8_t *buf, size_t bufsize)
{
    return getrandom(buf, bufsize, 0) == -1 ? -1 : 0;
}
