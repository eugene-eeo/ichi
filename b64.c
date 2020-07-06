#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "monocypher/monocypher.h"
#include "base64/base64.h"
#include "utils.h"

#define err(...)       _err("b64", __VA_ARGS__)
#define WIPE_CTX(ctx)  crypto_wipe(ctx, sizeof(*(ctx)))

static const char* HELP =
    "usage: b64 -h\n"
    "       b64 [-e] [-w <length>]\n"
    "       b64 -d\n"
    "args:\n"
    "  -h           show help\n"
    "  -e           encode (default) stdin\n"
    "  -w <length>  set line wrap length (>=0, default: 76)\n"
    "  -d           decode stdin\n"
    ;

int encode(FILE* fp, size_t wrap);
int decode(FILE* fp);

int wraplines(size_t *so_far, size_t max, const uint8_t *buf, size_t bufsize, int final)
{
    if (max == 0)
        return _write(stdout, buf, bufsize);

    size_t i = 0;
    while (i < bufsize) {
        size_t remainder = max - *so_far;
        size_t to_write = remainder > (bufsize - i) ? (bufsize - i) : remainder;
        if (_write(stdout, buf + i, to_write) != 0)
            return -1;

        i += to_write;
        *so_far += to_write;
        if (*so_far == max && to_write > 0) {
            *so_far = 0;
            if (_write(stdout, (uint8_t*)"\n", 1) != 0)
                return -1;
        }
    }
    if (final && *so_far != 0 && _write(stdout, (uint8_t*)"\n", 1) != 0)
        return -1;
    return 0;
}

uint8_t *unwraplines(uint8_t *head, const uint8_t *buf, size_t bufsize)
{
    if (head >= buf + bufsize)
        return NULL;
    uint8_t* tail = memchr(head, '\n', bufsize - (head - buf));
    if (tail == NULL) {
        tail = head + bufsize - (head - buf);
    }
    return tail;
}

int encode(FILE* fp, size_t wrap)
{
#define __error(m) { err(m); goto error; }

    int rv = 1;
    size_t bufsize = 1024,
           encsize = b64_encode_update_size(bufsize);
    uint8_t *buf = malloc(1024),
            *enc = malloc(encsize);
    if (buf == NULL || enc == NULL)
        __error("malloc");

    size_t so_far = 0; // state for wraplines
    b64_encode_ctx ctx;
    b64_encode_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, bufsize, fp);
        if (ferror(fp))
            __error("fread");
        size_t m = b64_encode_update(&ctx, enc, buf, n);
        if (wraplines(&so_far, wrap, enc, m, 0) != 0)
            __error("fwrite");
        if (feof(fp)) {
            m = b64_encode_final(&ctx, enc);
            if (wraplines(&so_far, wrap, enc, m, 1) != 0)
                __error("fwrite");
            break;
        }
    }

    rv = 0;
error:
    WIPE_CTX(&ctx);
    _free(buf, bufsize);
    _free(enc, encsize);
    return rv;

#undef __error
}

int decode(FILE* fp)
{
#define __error(m) { err(m); goto error; }

    int rv = 1;
    size_t bufsize = 1024,
           decsize = b64_decode_update_size(bufsize);
    uint8_t *buf = malloc(1024),
            *dec = malloc(decsize);
    if (buf == NULL || dec == NULL)
        __error("malloc");

    b64_decode_ctx ctx;
    b64_decode_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, bufsize, fp);
        if (ferror(fp))
            __error("fread");

        uint8_t *head = buf;
        uint8_t *tail;
        while ((tail = unwraplines(head, buf, n)) != NULL) {
            size_t m = b64_decode_update(&ctx, dec, head, tail - head);
            if (b64_decode_err(&ctx))
                __error("invalid base64");
            if (_write(stdout, dec, m) != 0)
                __error("fwrite");
            head = tail + 1;
        }

        if (feof(fp)) {
            b64_decode_final(&ctx);
            if (b64_decode_err(&ctx))
                __error("invalid base64");
            break;
        }
    }

    rv = 0;
error:
    WIPE_CTX(&ctx);
    _free(buf, bufsize);
    _free(dec, decsize);
    return rv;

#undef __error
}

int main(int argc, char **argv)
{
    size_t wrap = 76;
    char *tmp;
    int rv = 1;
    int c;
    char action = 'e';
    while ((c = getopt(argc, argv, "hedw:")) != -1)
        switch (c) {
            default:
                err("invalid usage: see b64 -h");
                goto error;
            case 'h':
                printf("%s", HELP);
                rv = 0;
                goto error;
            case 'w':
                errno = 0;
                wrap = strtol(optarg, &tmp, 10);
                if (errno || tmp == optarg) {
                    err("invalid argument to -w");
                    goto error;
                }
                break;
            case 'e': action = 'e'; break;
            case 'd': action = 'd'; break;
        }
    switch (action) {
        case 'e': rv = encode(stdin, wrap); break;
        case 'd': rv = decode(stdin); break;
    }
error:
    return rv;
}
