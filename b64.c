#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "monocypher/monocypher.h"
#include "base64/base64.h"
#include "utils.h"

#define err(...) {\
    fprintf(stderr, "b64: ");\
    fprintf(stderr, __VA_ARGS__);\
    if (errno) {\
        fprintf(stderr, ": ");\
        perror(NULL);\
    }\
    else fprintf(stderr, "\n");\
}
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

uint8_t *unwraplines(      uint8_t *head,
                     const uint8_t *buf, size_t bufsize)
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
    int rv = 1;
    size_t bufsize = 1024,
           encsize = b64_encode_update_size(bufsize);
    uint8_t *buf = malloc(1024),
            *enc = malloc(encsize);
    if (buf == NULL || enc == NULL)
        goto error;

    size_t so_far = 0; // state for wraplines
    b64_encode_ctx ctx;
    b64_encode_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, bufsize, fp);
        if (ferror(fp)) {
            err("cannot read");
            goto error;
        }
        size_t m = b64_encode_update(&ctx, enc, buf, n);
        if (wraplines(&so_far, wrap, enc, m, 0) != 0) {
            err("cannot write");
            goto error;
        }
        if (feof(fp)) {
            m = b64_encode_final(&ctx, enc);
            if (wraplines(&so_far, wrap, enc, m, 1) != 0) {
                err("cannot write");
                goto error;
            }
            break;
        }
    }

    rv = 0;
error:
    crypto_wipe(ctx.buf, sizeof(ctx.buf));
    if (buf != NULL) _free(buf, bufsize);
    if (enc != NULL) _free(enc, encsize);
    return rv;
}

int decode(FILE* fp)
{
    int rv = 1;

    size_t bufsize = 1024,
           decsize = b64_decode_update_size(bufsize);
    uint8_t *buf = malloc(1024),
            *dec = malloc(decsize);
    if (buf == NULL || dec == NULL)
        goto error;

    b64_decode_ctx ctx;
    b64_decode_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, bufsize, fp);
        if (ferror(fp)) {
            err("cannot read");
            goto error;
        }

        uint8_t *head = buf;
        uint8_t *tail;
        while ((tail = unwraplines(head, buf, n)) != NULL) {
            size_t m = b64_decode_update(&ctx, dec, head, tail - head);
            if (b64_decode_err(&ctx)) {
                err("invalid base64");
                goto error;
            }
            if (_write(stdout, dec, m) != 0) {
                err("cannot write");
                goto error;
            }
            head = tail + 1;
        }

        if (feof(fp)) {
            b64_decode_final(&ctx);
            if (b64_decode_err(&ctx)) {
                err("invalid base64");
                goto error;
            }
            break;
        }
    }

    rv = 0;
error:
    crypto_wipe(ctx.buf, sizeof(ctx.buf));
    if (buf != NULL) _free(buf, bufsize);
    if (dec != NULL) _free(dec, decsize);
    return rv;
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
