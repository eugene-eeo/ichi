#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

#include "monocypher/monocypher.h"
#include "utils.h"

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
    "       luck -{e|d}k <key> [FILE]\n\n"
    "args:\n"
    "  FILE       file for encryption/decryption (default: stdin).\n\n"
    "options:\n"
    "  -h         show help\n"
    "  -g <base>  generate keypair in <key>.sk (secret) and <key>.pk (public)\n"
    "  -wk <key>  print public key for secret key <key>\n"
    "  -ek <key>  encrypt FILE for receipient with pubkey <key>\n"
    "  -dk <key>  decrypt FILE with secret key <key>\n\n"
    ;

static const uint8_t HEAD_BLOCK  = 'b';
static const uint8_t HEAD_DIGEST = '$';

int generate_keypair(char *base);
int write_pubkey(FILE *key_fp);
int encrypt(FILE *fp, FILE *key_fp);
int decrypt(FILE *fp, FILE *key_fp);


static void increment_nonce(uint8_t buf[24])
{
    for (size_t i = 0; i < 24 && buf[i] == 255; i++)
        buf[i]++;
}

void ls_lock(uint8_t       *output,  // input_size + 34
             uint8_t        nonce [24],
             const uint8_t  key   [32],
             const uint8_t *input, size_t input_size)
{
    uint8_t length[2];
    length[0] = (input_size)      & 0xFF;
    length[1] = (input_size >> 8) & 0xFF;

    increment_nonce(nonce);
    crypto_lock(output,
                output + 16, /* mac */
                key, nonce,
                length, 2);

    increment_nonce(nonce);
    crypto_lock(output + 18,
                output + 18 + 16, /* mac */
                key, nonce,
                input, input_size);
    crypto_wipe(length, sizeof(length));
}

int ls_unlock_length(size_t        *to_read,
                     uint8_t        nonce [24],
                     const uint8_t  key   [32],
                     const uint8_t  input [18])
{
    int rv = -1;
    uint8_t length_buf[2];
    increment_nonce(nonce);
    if (crypto_unlock(length_buf,
                      key, nonce,
                      input /* mac */,
                      input + 16, 2) != 0)
        goto error;
    rv = 0;
    // convert back to integer
    *to_read =   (size_t) length_buf[0]
             + (((size_t) length_buf[1]) << 8);
error:
    crypto_wipe(length_buf, sizeof(length_buf));
    return rv;
}

int ls_unlock_payload(uint8_t        *output,
                      uint8_t        nonce [24],
                      const uint8_t  key   [32],
                      const uint8_t  *input, size_t input_size)
{
    increment_nonce(nonce);
    return crypto_unlock(output,
                         key, nonce,
                         input, /* mac */
                         input + 16, input_size);
}

int generate_keypair(char *base)
{
    int rv = 1;
    uint8_t sk[32],
            pk[32];

    if (getrandom(sk, sizeof(sk), 0) < 0) {
        err("cannot generate keypair");
        goto error_1;
    }

    crypto_key_exchange_public_key(pk, sk);

    size_t len = strlen(base);
    FILE* fp;
    char* fn = malloc(len + 4);
    if (fn == NULL) {
        err("cannot malloc");
        goto error_1;
    }

    // Secret key
    memcpy(fn, base, len);
    memcpy(fn + len,  ".sk", 3);
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(sk, 1, sizeof(sk), fp) != sizeof(sk)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        err("cannot write secret key in '%s'", fn);
        goto error_2;
    }

    // Public key
    memcpy(fn + len,  ".pk", 3);
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(pk, 1, sizeof(pk), fp) != sizeof(pk)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        err("cannot write public key in '%s'", fn);
        goto error_2;
    }

    rv = 0;

error_2:
    if (fp != NULL)
        fclose(fp);
    _free(fn, len + 4);
error_1:
    crypto_wipe(sk, sizeof(sk));
    crypto_wipe(pk, sizeof(pk));
    return rv;
}

int write_pubkey(FILE* fp)
{
    int rv = 1;
    uint8_t sk[32],
            pk[32];

    if (_read(fp, sk, 32) != 0) {
        err("invalid secret key");
        goto error;
    }

    crypto_key_exchange_public_key(pk, sk);

    if (_write(stdout, pk, sizeof(pk)) != 0
            || _write(stdout, (uint8_t *) "\n", 1) != 0) {
        err("cannot write");
        goto error;
    }
    rv = 0;

error:
    crypto_wipe(pk, sizeof(pk));
    crypto_wipe(sk, sizeof(sk));
    return rv;
}

#define __check_write(x) { if ((x) != 0) { err("cannot write"); goto error_2; } }

// Encrypt data for key_fp
int encrypt(FILE* fp, FILE* key_fp)
{
    int rv = 1;
    uint8_t eph_sk     [32],
            eph_pk     [32],
            pk         [32],
            shared_key [32];

    if (_read(key_fp, pk, 32) != 0) {
        err("invalid public key");
        goto error_1;
    }

    if (getrandom(eph_sk, sizeof(eph_sk), 0) < 0) {
        err("cannot generate random key");
        goto error_1;
    }

    crypto_key_exchange_public_key(eph_pk, eph_sk);
    crypto_key_exchange(shared_key, eph_sk, pk);

    size_t raw_buf_size = 4096,
           enc_buf_size = 4096 + 34;

    uint8_t *raw_buf = malloc(raw_buf_size),
            *enc_buf = malloc(enc_buf_size);
    if (raw_buf == NULL || enc_buf == NULL) {
        err("cannot malloc");
        goto error_2;
    }

    uint8_t nonce[24] = { 0 };
    __check_write(_write(stdout, eph_pk, sizeof(eph_pk)));

    uint8_t digest[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, shared_key, 32);

    size_t n;
    for (;;) {
        n = fread(raw_buf, 1, raw_buf_size, fp);
        if (ferror(fp)) {
            err("cannot read");
            goto error_2;
        }
        if (n > 0) {
            crypto_blake2b_update(&ctx, raw_buf, n);
            ls_lock(enc_buf,
                    nonce,
                    shared_key,
                    raw_buf, n);
            __check_write(_write(stdout, &HEAD_BLOCK, 1));
            __check_write(_write(stdout, enc_buf, n + 34));
        }
        if (feof(fp)) {
            crypto_blake2b_final(&ctx, digest);
            __check_write(_write(stdout, &HEAD_DIGEST, 1));
            __check_write(_write(stdout, digest, 64));
            break;
        }
    }
    rv = 0;

error_2:
    _free(raw_buf, raw_buf_size);
    _free(enc_buf, enc_buf_size);
error_1:
    n = 0;
    crypto_wipe(digest,     sizeof(digest));
    crypto_wipe(nonce,      sizeof(nonce));
    crypto_wipe(shared_key, sizeof(shared_key));
    crypto_wipe(eph_sk,     sizeof(eph_sk));
    crypto_wipe(eph_pk,     sizeof(eph_pk));
    crypto_wipe(pk,         sizeof(pk));
    return rv;
}

#define __check_read(x)   { if ((x) != 0) { err("bad encryption: cannot read");   goto error_2; } }
#define __check_unlock(x) { if ((x) != 0) { err("bad encryption: cannot unlock"); goto error_2; } }

int decrypt(FILE* fp, FILE* key_fp)
{
    int rv = 1;
    uint8_t eph_pk     [32],
            sk         [32],
            shared_key [32];

    if (_read(key_fp, sk, 32) != 0) {
        err("invalid secret key");
        goto error_1;
    }

    if (_read(fp, eph_pk, 32) != 0) {
        err("invalid encryption");
        goto error_1;
    }

    crypto_key_exchange(shared_key, sk, eph_pk);

    size_t raw_buf_size = 4096 + 34,
           dec_buf_size = 4096;
    uint8_t *raw_buf = malloc(raw_buf_size),
            *dec_buf = malloc(dec_buf_size);
    if (raw_buf == NULL || dec_buf == NULL) {
        err("malloc failed");
        goto error_2;
    }

    uint8_t nonce[24] = { 0 };
    uint8_t digest[64];
    uint8_t head;
    size_t length; // length of each BLOCK chunk
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, shared_key, 32);

    int done = 0;
    while (!done) {
        // read head byte
        __check_read(_read(fp, &head, 1));
        switch (head) {
            default:
                err("bad encryption");
                goto error_2;
            case HEAD_BLOCK:
            {
                __check_read(  _read(fp, raw_buf, 18));
                __check_unlock(ls_unlock_length(&length, nonce, shared_key, raw_buf));
                __check_read(  _read(fp, raw_buf, length + 16));
                __check_unlock(ls_unlock_payload(dec_buf, nonce, shared_key, raw_buf, length));
                if (_write(stdout, dec_buf, length) != 0) {
                    err("cannot write");
                    goto error_2;
                }
                crypto_blake2b_update(&ctx, dec_buf, length);
                break;
            }
            case HEAD_DIGEST:
            {
                crypto_blake2b_final(&ctx, digest);
                __check_read(  _read(fp, raw_buf, 64));
                __check_unlock(crypto_verify64(digest, raw_buf));
                // expect EOF - do one extra read here otherwise we cannot
                // detect EOF.
                if (fread(raw_buf, 1, 1, fp) == 1 || !feof(fp)) {
                    err("expected EOF");
                    goto error_2;
                }
                done = 1;
                rv = 0;
                break;
            }
        }
    }

error_2:
    _free(raw_buf, raw_buf_size);
    _free(dec_buf, dec_buf_size);
error_1:
    length = 0;
    head = 0;
    crypto_wipe(digest,     sizeof(digest));
    crypto_wipe(nonce,      sizeof(nonce));
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
            rv = 0;
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
    if (no_argc && argc > optind) {
        err("%s", SEE_HELP);
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
    default:  err("%s", SEE_HELP);         break;
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
    return rv;
}
