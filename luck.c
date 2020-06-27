#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

#include "monocypher/monocypher.h"

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
    "       luck -{e|d}k <key> [file]\n"
    "\nargs:\n"
    "  file       file for encryption/decryption (default: stdin).\n"
    "\noptions:\n"
    "  -h         show help\n"
    "  -g <base>  generate keypair in <key>.sk (secret) and <key>.pk (public)\n"
    "  -wk <key>  print public key for secret key <key>\n"
    "  -ek <key>  encrypt file for receipient with pubkey <key>\n"
    "  -dk <key>  decrypt file with secret key <key>\n"
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

void ls_lock(      uint8_t *output,  // input_size + 34
                   uint8_t  nonce [24],
             const uint8_t  key   [32],
             const uint8_t *input, size_t input_size)
{
    uint8_t length[2];
    length[0] = (input_size)      & 0xFF;
    length[1] = (input_size >> 8) & 0xFF;

    increment_nonce(nonce);
    crypto_lock(output,
                output + 16 /* mac */,
                key, nonce,
                length, 2);

    increment_nonce(nonce);
    crypto_lock(output + 18,
                output + 18 + 16 /* mac */,
                key, nonce,
                input, input_size);
}

int ls_unlock_length(size_t        *to_read,
                     uint8_t        nonce [24],
                     const uint8_t  key   [32],
                     const uint8_t  input [18]) // 16 + 2
{
    uint8_t length_buf[2];
    increment_nonce(nonce);
    if (crypto_unlock(length_buf,
                      key, nonce,
                      input /* mac */,
                      input + 16, 2) != 0)
        return -1;
    // convert back to integer
    *to_read =   (size_t) length_buf[0]
             + (((size_t) length_buf[1]) << 8);
    return 0;
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

int _fclose(FILE** fp)
{
    int rv = fclose(*fp);
    *fp = NULL;
    return rv;
}

int write_exactly(const uint8_t *buf, size_t bufsize, FILE* fp)
{
    return (fwrite(buf, 1, bufsize, fp) == bufsize) ? 0 : -1;
}

int read_exactly(uint8_t *buf, size_t bufsize, FILE* fp)
{
    return (fread(buf, 1, bufsize, fp) == bufsize) ? 0 : -1;
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
    char* fn = calloc(1, strlen(base) + 4);
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
    free(fn);
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

    if (read_exactly(sk, 32, fp) != 0) {
        err("invalid secret key");
        goto error;
    }

    crypto_key_exchange_public_key(pk, sk);

    if (fwrite(pk, 1, sizeof(pk), stdout) != sizeof(pk)
            || fwrite("\n", 1, 1, stdout) != 1) {
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

    if (read_exactly(pk, 32, key_fp) != 0) {
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
    __check_write(write_exactly(eph_pk, sizeof(eph_pk), stdout));

    uint8_t digest[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, shared_key, 32);

    for (;;) {
        size_t n = fread(raw_buf, 1, raw_buf_size, fp);
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
            __check_write(write_exactly(&HEAD_BLOCK, 1, stdout));
            __check_write(write_exactly(enc_buf, n + 34, stdout));
        }
        if (feof(fp)) {
            crypto_blake2b_final(&ctx, digest);
            __check_write(write_exactly(&HEAD_DIGEST, 1, stdout));
            __check_write(write_exactly(digest, 64, stdout));
            break;
        }
    }
    rv = 0;

error_2:
    if (raw_buf != NULL) { crypto_wipe(raw_buf, raw_buf_size); free(raw_buf); }
    if (enc_buf != NULL) { crypto_wipe(enc_buf, enc_buf_size); free(enc_buf); }
error_1:
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

    if (read_exactly(sk, 32, key_fp) != 0) {
        err("invalid secret key");
        goto error_1;
    }

    if (read_exactly(eph_pk, 32, fp) != 0) {
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
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, shared_key, 32);

    int done = 0;
    while (!done) {
        // read head byte
        uint8_t head;
        __check_read(read_exactly(&head, 1, fp));
        switch (head) {
            default:
                err("bad encryption");
                goto error_2;
            case HEAD_BLOCK:
            {
                size_t length = 0;
                __check_read(  read_exactly(raw_buf, 18, fp));
                __check_unlock(ls_unlock_length(&length, nonce, shared_key, raw_buf));
                __check_read(  read_exactly(raw_buf, length + 16, fp));
                __check_unlock(ls_unlock_payload(dec_buf, nonce, shared_key, raw_buf, length));
                if (write_exactly(dec_buf, length, stdout) != 0) {
                    err("cannot write");
                    goto error_2;
                }
                crypto_blake2b_update(&ctx, dec_buf, length);
                break;
            }
            case HEAD_DIGEST:
            {
                // compare our digest vs real
                crypto_blake2b_final(&ctx, digest);
                __check_read(  read_exactly(raw_buf, 64, fp));
                __check_unlock(crypto_verify64(digest, raw_buf));
                // expect EOF - do one extra read here otherwise we cannot
                // detect EOF.
                if (fread(raw_buf, 1, 1, fp) == 1 || !feof(fp)) {
                    err("expected to be EOF");
                    goto error_2;
                }
                done = 1;
                rv = 0;
                break;
            }
        }
    }

error_2:
    if (raw_buf != NULL) { crypto_wipe(raw_buf, raw_buf_size); free(raw_buf); }
    if (dec_buf != NULL) { crypto_wipe(dec_buf, dec_buf_size); free(dec_buf); }
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
            printf("%s\n", HELP);
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
    if (no_argc && argc - optind > 0) {
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
    if (fclose(stderr) != 0) {
        err("cannot close stderr");
        rv = 1;
    }
    return rv;
}
