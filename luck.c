#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

#include "monocypher/monocypher.h"
#include "base64/base64.h"

#define B64_KEY_SIZE 44
#define err(...) {\
    fprintf(stderr, "luck: ");\
    fprintf(stderr, __VA_ARGS__);\
    if (errno) {\
        fprintf(stderr, ": ");\
        perror(NULL);\
    }\
    else fprintf(stderr, "\n");\
}

static const char* SEE_HELP = "invalid usage: see luck -h";
static const char* HELP =
    "usage: luck -h\n"
    "       luck -g <base>\n"
    "       luck -wk <key>\n"
    "       luck -ek <key> [file]\n"
    "       luck -dk <key> [file]\n"
    "\nargs:\n"
    "  file       file for encryption/decryption (default: stdin).\n"
    "\noptions:\n"
    "  -h         show help\n"
    "  -g <base>  generate keypair at <key>.sk (secret) and <key>.pk (public)\n"
    "  -wk <key>  print public key of secret key <key>\n"
    "  -ek <key>  encrypt file for receipient with pubkey <key>\n"
    "  -dk <key>  decrypt file with secret key <key>\n"
    ;

static const uint8_t zeros[24] = { 0 };


int generate_keypair(char *base);
int write_pubkey(FILE *key_fp);
int encrypt(FILE *fp, FILE *key_fp);
int decrypt(FILE *fp, FILE *key_fp);


typedef struct {
    uint8_t  buf[64];
    uint8_t  bufsize;
    uint8_t  key[32];
    uint64_t ctr;
} xchacha20_ctx;


void xchacha20_init(xchacha20_ctx *ctx, uint8_t* shared_key)
{
    memcpy(ctx->key, shared_key, 32);
    ctx->bufsize = 0;
    ctx->ctr = 0;
}

size_t xchacha20_update_size(size_t bufsize)
{
    return bufsize + 64;
}

size_t xchacha20_update(xchacha20_ctx *ctx,
                        uint8_t* out,
                        const uint8_t* buf, size_t bufsize)
{
    size_t i = 0;
    size_t n = 0;
    // load into buffer
    if (ctx->bufsize > 0) {
        while (ctx->bufsize < 64 && i < bufsize) {
            ctx->buf[ctx->bufsize] = buf[i];
            ctx->bufsize++;
            i++;
        }
        if (ctx->bufsize < 64)
            return 0;
        // consume
        ctx->bufsize = 0;
        ctx->ctr = crypto_xchacha20_ctr(out + n,
                                        ctx->buf, 64,
                                        ctx->key, zeros, ctx->ctr);
        n += 64;
    }
    for (; i + 64 < bufsize; i += 64, n += 64)
        ctx->ctr = crypto_xchacha20_ctr(out + n,
                                        buf + i, 64,
                                        ctx->key, zeros, ctx->ctr);
    // everything not fitting into 64 bytes
    // goes into buffer
    for (; i < bufsize; i++) {
        ctx->buf[ctx->bufsize] = buf[i];
        ctx->bufsize++;
    }
    return n;
}

size_t xchacha20_final(xchacha20_ctx *ctx, uint8_t *out)
{
    size_t n = 0;
    if (ctx->bufsize > 0) {
        // consume
        ctx->ctr = crypto_xchacha20_ctr(out,
                                        ctx->buf, ctx->bufsize,
                                        ctx->key,
                                        zeros,
                                        ctx->ctr);
        n += ctx->bufsize;
    }
    crypto_wipe(ctx->key, 32);
    crypto_wipe(ctx->buf, 64);
    ctx->bufsize = 0;
    ctx->ctr = 0;
    return n;
}


int _fclose(FILE** fp)
{
    int rv = fclose(*fp);
    *fp = NULL;
    return rv;
}

void concat_str(char* dst, char* a, char* b)
{
    size_t a_size = strlen(a),
           b_size = strlen(b);
    memcpy(dst,          a, a_size);
    memcpy(dst + a_size, b, b_size);
    dst[a_size + b_size] = 0;
}

int read_exactly(uint8_t *buf, size_t bufsize, FILE* fp)
{
    if (fread(buf, 1, bufsize, fp) == bufsize)
        return 0;
    return -1;
}

int decode_exactly(      uint8_t* out, size_t outsize,
                   const uint8_t *buf, size_t bufsize)
{
    if (b64_validate(buf, bufsize) != 0 || b64_decoded_size(buf, bufsize) != outsize)
        return -1;
    b64_decode(out, buf, bufsize);
    return 0;
}

int key_from_file(uint8_t key[32], FILE* fp)
{
    int rv = -1;
    uint8_t b64_key[B64_KEY_SIZE];
    if (read_exactly(b64_key, sizeof(b64_key), fp) == 0
            && decode_exactly(key, 32, b64_key, sizeof(b64_key)) == 0) {
        rv = 0;
    }
    crypto_wipe(b64_key, sizeof(b64_key));
    return rv;
}

int wraplines(size_t *line_length,
              size_t max_length,
              const uint8_t* buf, size_t bufsize,
              int final,
              FILE* fp)
{
    size_t offset = 0;
    while (bufsize > 0) {
        size_t remainder = max_length - *line_length,
               to_write  = remainder <= bufsize ? remainder : bufsize;

        if (fwrite(buf + offset, 1, to_write, fp) != to_write)
            return -1;

        *line_length = *line_length + to_write;
        if (*line_length == max_length) {
            *line_length = 0;
            if (fwrite("\n", 1, 1, fp) != 1)
                return -1;
        }
        offset += to_write;
        bufsize -= to_write;
    }
    if (final && *line_length != 0)
        if (fwrite("\n", 1, 1, fp) != 1)
            return -1;
    return 0;
}

int generate_keypair(char *base)
{
    int rv = 1;
    uint8_t sk      [32],
            pk      [32],
            b64_key [B64_KEY_SIZE];
    if (getrandom(sk, sizeof(sk), 0) < 0) {
        err("cannot generate keypair");
        goto error_1;
    }

    crypto_key_exchange_public_key(pk, sk);

    FILE* fp;
    char* fn = malloc(strlen(base) + 4);
    if (fn == NULL) {
        err("cannot malloc");
        goto error_1;
    }

    // Secret key
    b64_encode(b64_key, sk, sizeof(sk));
    concat_str(fn, base, ".sk");
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(b64_key, 1, sizeof(b64_key), fp) != sizeof(b64_key)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        err("cannot write %s", fn);
        goto error_2;
    }

    // Public key
    b64_encode(b64_key, pk, sizeof(pk));
    concat_str(fn, base, ".pk");
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(b64_key, 1, sizeof(b64_key), fp) != sizeof(b64_key)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        err("cannot write %s", fn);
        goto error_2;
    }

    rv = 0;

error_2:
    if (fp != NULL)
        fclose(fp);
    free(fn);
error_1:
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(pk, sizeof(pk));
    crypto_wipe(b64_key, sizeof(b64_key));
    return rv;
}

int write_pubkey(FILE* fp)
{
    int rv = 1;
    uint8_t sk     [32],
            pk     [32],
            b64_pk [B64_KEY_SIZE];

    if (key_from_file(sk, fp) != 0) {
        err("invalid secret key");
        goto error;
    }

    crypto_key_exchange_public_key(pk, sk);
    b64_encode(b64_pk, pk, sizeof(pk));

    if (fwrite(b64_pk, 1, sizeof(b64_pk), stdout) != sizeof(b64_pk)
     || fwrite("\n",   1,              1, stdout) != 1) {
        err("cannot write");
        goto error;
    }
    rv = 0;

error:
    crypto_wipe(pk, 32);
    crypto_wipe(sk, 32);
    return rv;
}

// Encrypt data for key_fp
int encrypt(FILE* fp, FILE* key_fp)
{
    int rv = 1;
    uint8_t eph_sk     [32],
            eph_pk     [32],
            pk         [32],
            shared_key [32],
            b64_eph_pk [B64_KEY_SIZE];

    if (key_from_file(pk, key_fp) != 0) {
        err("invalid public key");
        goto error_1;
    }

    if (getrandom(eph_sk, sizeof(eph_sk), 0) < 0) {
        err("cannot generate random key");
        goto error_1;
    }

    size_t raw_buf_size = 1024,
           enc_buf_size = xchacha20_update_size(raw_buf_size),
           b64_buf_size = b64_encode_update_size(enc_buf_size);

    uint8_t *raw_buf = malloc(raw_buf_size),
            *enc_buf = malloc(enc_buf_size),
            *b64_buf = malloc(b64_buf_size);
    if (raw_buf == NULL || enc_buf == NULL || b64_buf == NULL) {
        err("cannot malloc");
        goto error_2;
    }

    crypto_key_exchange_public_key(eph_pk, eph_sk);
    crypto_key_exchange(shared_key, eph_sk, pk);

    b64_encode(b64_eph_pk, eph_pk, sizeof(eph_pk));
    if (fwrite(b64_eph_pk, 1, sizeof(b64_eph_pk), stdout) != sizeof(b64_eph_pk)
     || fwrite("\n",       1,                  1, stdout) != 1) {
        err("cannot write");
        goto error_2;
    }

    size_t m;
    size_t l = 0; // ctx for wraplines

    xchacha20_ctx xctx;
    xchacha20_init(&xctx, shared_key);

    b64_encode_ctx ctx;
    b64_encode_init(&ctx);

    for (;;) {
        size_t n = fread(raw_buf, 1, 1024, fp);
        if (ferror(fp)) {
            err("error reading file");
            goto error_2;
        }
        n = xchacha20_update(&xctx, enc_buf, raw_buf, n);
        m = b64_encode_update(&ctx, b64_buf, enc_buf, n);
        if (wraplines(&l, 64, b64_buf, m, 0, stdout) != 0) {
            err("cannot write");
            goto error_2;
        }
        if (feof(fp)) {
            n = xchacha20_final(&xctx, enc_buf);
            m = b64_encode_update(&ctx, b64_buf, enc_buf, n);
            if (wraplines(&l, 64, b64_buf, m, 0, stdout) != 0) {
                err("cannot write");
                goto error_2;
            }

            m = b64_encode_final(&ctx, b64_buf);
            if (wraplines(&l, 64, b64_buf, m, 1, stdout) != 0) {
                err("cannot write");
                goto error_2;
            }
            break;
        }
    }
    rv = 0;

error_2:
    crypto_wipe(ctx.buf, 3);
    crypto_wipe(xctx.buf, 64);
    if (raw_buf != NULL) { crypto_wipe(raw_buf, raw_buf_size); free(raw_buf); }
    if (enc_buf != NULL) { crypto_wipe(enc_buf, enc_buf_size); free(enc_buf); }
    if (b64_buf != NULL) { crypto_wipe(b64_buf, b64_buf_size); free(b64_buf); }
error_1:
    crypto_wipe(b64_eph_pk, sizeof(b64_eph_pk));
    crypto_wipe(shared_key, sizeof(shared_key));
    crypto_wipe(eph_sk,     sizeof(eph_sk));
    crypto_wipe(eph_pk,     sizeof(eph_pk));
    crypto_wipe(pk,         sizeof(pk));
    return rv;
}

int decrypt(FILE* fp, FILE* key_fp)
{
    int rv = 1;
    uint8_t eph_pk     [32],
            sk         [32],
            shared_key [32];

    if (key_from_file(sk, key_fp) != 0) {
        err("invalid secret key");
        goto error_1;
    }

    if (key_from_file(eph_pk, fp) != 0) {
        err("invalid encryption");
        goto error_1;
    }

    crypto_key_exchange(shared_key, sk, eph_pk);

    size_t b64_buf_size = 1024,
           raw_buf_size = b64_decode_update_size(b64_buf_size),
           enc_buf_size = xchacha20_update_size(raw_buf_size);
    uint8_t *b64_buf = malloc(b64_buf_size),
            *raw_buf = malloc(raw_buf_size),
            *enc_buf = malloc(enc_buf_size);
    if (b64_buf == NULL || raw_buf == NULL || enc_buf == NULL) {
        err("malloc failed");
        goto error_2;
    }

    xchacha20_ctx  xctx; xchacha20_init(&xctx, shared_key);
    b64_decode_ctx ctx;  b64_decode_init(&ctx);

    for (;;) {
        size_t n = fread(b64_buf, 1, 1024, fp);
        if (ferror(fp)) {
            err("cannot read");
            goto error_2;
        }
        size_t r = 0;
        for (size_t i = 0; i <= n; i++) {
            if (i == n || b64_buf[i] == '\n') {
                size_t m = b64_decode_update(&ctx, raw_buf, b64_buf + i - r, r);
                size_t x = xchacha20_update(&xctx, enc_buf, raw_buf, m);
                r = 0;
                if (fwrite(enc_buf, 1, x, stdout) < x) {
                    err("cannot write");
                    goto error_2;
                }
            } else {
                r++;
            }
        }
        if (feof(fp)) {
            size_t m = b64_decode_final(&ctx, raw_buf);
            size_t x = xchacha20_update(&xctx, enc_buf, raw_buf, m);
            if (fwrite(enc_buf, 1, x, stdout) < x) {
                err("cannot write");
                goto error_2;
            }

            x = xchacha20_final(&xctx, enc_buf);
            if (fwrite(enc_buf, 1, x, stdout) < x) {
                err("cannot write");
                goto error_2;
            }
            break;
        }
    }

error_2:
    crypto_wipe(ctx.buf, 4);
    crypto_wipe(xctx.buf, 64);
    if (b64_buf != NULL) { crypto_wipe(b64_buf, b64_buf_size); free(b64_buf); }
    if (raw_buf != NULL) { crypto_wipe(raw_buf, raw_buf_size); free(raw_buf); }
    if (enc_buf != NULL) { crypto_wipe(enc_buf, enc_buf_size); free(enc_buf); }
error_1:
    crypto_wipe(eph_pk,     sizeof(eph_pk));
    crypto_wipe(sk,         sizeof(sk));
    crypto_wipe(shared_key, sizeof(shared_key));
    return rv;
}

int main(int argc, char** argv)
{
    int rv = 1;
    FILE* fp     = NULL;
    FILE* key_fp = NULL;
    char* base = NULL;
    int action = 0;
    int c;
    int no_argc = 0;  // whether we expect argc
    int expect_fp   = 0;  // expect fp
    int expect_key  = 0;  // expect key

    while ((c = getopt(argc, argv, "hg:wedk:")) != -1)
        switch (c) {
        default: err("%s", SEE_HELP); goto out;
        case 'h':
            printf("%s", HELP);
            goto out;
        case 'g': action = 'g'; no_argc = 1;   base = optarg;  break;
        case 'w': action = 'w'; no_argc = 1;   expect_key = 1; break;
        case 'e': action = 'e'; expect_fp = 1; expect_key = 1; break;
        case 'd': action = 'd'; expect_fp = 1; expect_key = 1; break;
        case 'k':
            key_fp = fopen(optarg, "r");
            if (key_fp == NULL) {
                err("cannot open key file '%s'", optarg);
                goto out;
            }
            break;
        }

    if (expect_key && key_fp == NULL) {
        err("no key specified");
        goto out;
    }
    if (no_argc && argc - optind > 0) {
        err("invalid usage");
        goto out;
    }
    if (expect_fp) {
        if (argc == optind + 1) {
            fp = fopen(argv[optind], "r");
            if (fp == NULL) {
                err("cannot open '%s'", argv[optind]);
                goto out;
            }
        } else if (argc == optind) {
            fp = stdin;
        } else {
            err("%s", SEE_HELP);
            goto out;
        }
    }

    switch (action) {
    case 0:
        err("%s", SEE_HELP);
        break;
    case 'g': rv = generate_keypair(base); break;
    case 'w': rv = write_pubkey(key_fp);   break;
    case 'e': rv = encrypt(fp, key_fp);    break;
    case 'd': rv = decrypt(fp, key_fp);    break;
    }

out:
    if (fp     != NULL) fclose(fp);
    if (key_fp != NULL) fclose(key_fp);
    if (fclose(stdout) != 0) {
        err("cannot close stdout");
        rv = 1;
    }
    if (fclose(stderr) != 0) {
        err("cannot close stderr");
        rv = 1;
    }
    return rv;
}
