#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/random.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "base64/base64.h"
#include "monocypher/monocypher.h"

#define READ_SIZE (4096)
#define B64_KEY_SIZE 44  // b64_encoded_size(32)
#define B64_SIG_SIZE 88  // b64_encoded_size(64)
#define SEE_USAGE "invalid usage: see kurv -h"
#define err(...) {\
    fwrite("kurv: ", 1, 6, stderr);\
    fprintf(stderr, __VA_ARGS__);\
    if (errno) {\
        fprintf(stderr, ": ");\
        perror(NULL);\
    } else {\
        fprintf(stderr, "\n");\
    }\
}
static const char HELP[] =
    "usage: kurv -h\n"
    "       kurv -g <base>\n"
    "       kurv -d [FILE]\n"
    "       kurv -s -k <key> [FILE]\n"
    "       kurv -c [-k <key>] [-i] [FILE]\n"
    "\nargs:\n"
    "  FILE       (signed) file, defaults to stdin.\n"
    "\noptions:\n"
    "  -h          show help page.\n"
    "  -g <base>   generate keypair in <base>.priv and <base>.pub.\n"
    "  -d          print FILE contents without signature.\n"
    "  -k <key>    specify key file for signing / checking.\n"
    "  -s          sign FILE using given private key <key>.\n"
    "  -c          check FILE using public key <key>.\n"
    "              if <key> is not specified, try '$KURV_KEYRING/*.pub'\n"
    "              one by one.\n"
    "  -i          print path to public key used on successful check.\n\n"
    ;

static const char SIG_START[] = "\n----BEGIN KURV SIGNATURE----\n";
static const char SIG_END[]   = "\n----END KURV SIGNATURE----\n";

int generate_keypair(char* base);
int sign(FILE* fp, FILE* key_fp);
int check(FILE* fp, FILE* key_fp, int show_id, char* id);
int check_keyring(FILE* fp, int show_id);
int detach(FILE* fp);

int _read(FILE* fp, uint8_t* buf, size_t bufsize)
{
    return fread(buf, 1, bufsize, fp) == bufsize ? 0 : -1;
}

int _write(FILE* fp, const void* buf, size_t bufsize)
{
    return fwrite(buf, 1, bufsize, fp) == bufsize ? 0 : -1;
}

// decode base64 signature into sig
int decode_signature(uint8_t* sig, const uint8_t* b64_sig_buf) {
    int rv = 1;
    uint8_t b64_sig[B64_SIG_SIZE];

    memcpy(b64_sig,      b64_sig_buf,      44);
    memcpy(b64_sig + 44, b64_sig_buf + 45, 44);

    if (b64_sig_buf[44] == '\n'
            && b64_validate(b64_sig, B64_SIG_SIZE) == 0
            && b64_decoded_size(b64_sig, B64_SIG_SIZE) == 64) {
        b64_decode(sig, b64_sig, B64_SIG_SIZE);
        rv = 0;
    }
    crypto_wipe(b64_sig, B64_SIG_SIZE);
    return rv;
}

int key_from_file(FILE* fp, uint8_t key[32])
{
    int rv = 1;
    uint8_t b64_key[B64_KEY_SIZE];
    if (_read(fp, b64_key, B64_KEY_SIZE) == 0
            && b64_validate(b64_key, B64_KEY_SIZE) == 0
            && b64_decoded_size(b64_key, B64_KEY_SIZE) == 32) {
        b64_decode(key, b64_key, B64_KEY_SIZE);
        rv = 0;
    }
    crypto_wipe(b64_key, B64_KEY_SIZE);
    return rv;
}

int _fclose(FILE** fp)
{
    int rv = fclose(*fp);
    *fp = NULL;
    return rv;
}

void _free(void *buf, size_t size) {
    if (buf != NULL) {
        crypto_wipe(buf, size);
        free(buf);
    }
}

int str_endswith(char* str, char* suffix)
{
    size_t m = strlen(str),
           n = strlen(suffix);
    if (m < n) return -1;
    return memcmp(str + m - n, suffix, n);
}

int read_signed_file(FILE* fp, uint8_t digest[64], uint8_t sig[64])
{
    int rv = 1;
    size_t start_size = strlen(SIG_START),
           sig_size   = B64_SIG_SIZE + 1,
           end_size   = strlen(SIG_END),
           total_size = start_size + sig_size + end_size;

    size_t tmp_size = 0;
    uint8_t *buf = malloc(1024),
            *tmp = malloc(1024);
    if (buf == NULL || tmp == NULL) {
        err("malloc");
        goto error;
    }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, 1024, fp);
        // find signature
        if (feof(fp)) {
            uint8_t *sig_buf;
            if (n >= total_size) {
                crypto_blake2b_update(&ctx, tmp, tmp_size);
                crypto_blake2b_update(&ctx, buf, n - total_size);
                sig_buf = buf + n - total_size + start_size;
            } else {
                crypto_blake2b_update(&ctx, tmp, tmp_size - (total_size - n));
                // sig is now in buf
                memmove(buf + (total_size - n), buf, n);
                memcpy(buf, tmp + tmp_size - (total_size - n), total_size - n);
                sig_buf = buf + start_size;
            }

            if (decode_signature(sig, sig_buf) != 0) {
                err("malformed signature");
                goto error;
            }
            crypto_blake2b_final(&ctx, digest);
            rv = 0;
            break;
        }
        if (ferror(fp)) {
            err("cannot read");
            goto error;
        }
        crypto_blake2b_update(&ctx, tmp, tmp_size);
        memcpy(tmp, buf, n);
        tmp_size = n;
    }

error:
    _free(buf, 1024);
    _free(tmp, 1024);
    crypto_wipe((uint8_t *) &ctx, sizeof(ctx));
    return rv;
}

int generate_keypair(char* base)
{
    int rv = 1;
    uint8_t sk[32],
            pk[32],
            b64_sk[B64_KEY_SIZE],
            b64_pk[B64_KEY_SIZE];

    if (getrandom(sk, 32, 0) < 0) {
        err("cannot generate random key");
        goto error;
    }

    crypto_sign_public_key(pk, sk);
    b64_encode(b64_sk, sk, 32);
    b64_encode(b64_pk, pk, 32);

    size_t length = strlen(base);
    char* fn = malloc(length + 5 + 1);
    if (fn == NULL) {
        err("malloc");
        goto error;
    }

    // private key
    memcpy(fn, base, length);
    memcpy(fn + length, ".priv", 6);
    FILE* fp = fopen(fn, "w");
    if (fp == NULL
        || _write(fp, b64_sk, B64_KEY_SIZE) != 0
        || _write(fp, (uint8_t*) "\n", 1) != 0
        || _fclose(&fp) != 0) {
        err("cannot write private key in '%s'", fn);
        goto error_2;
    }

    // public key
    memcpy(fn + length, ".pub", 5);
    fp = fopen(fn, "w");
    if (fp == NULL
        || _write(fp, b64_pk, B64_KEY_SIZE) != 0
        || _write(fp, (uint8_t*) "\n", 1) != 0
        || _fclose(&fp) != 0) {
        err("cannot write public key in '%s'", fn);
        goto error_2;
    }
    rv = 0;

error_2:
    free(fn);
    if (fp != NULL)
        fclose(fp);
error:
    crypto_wipe(b64_sk, B64_KEY_SIZE);
    crypto_wipe(b64_pk, B64_KEY_SIZE);
    crypto_wipe(sk, 32);
    crypto_wipe(pk, 32);
    return rv;
}

int sign(FILE* fp, FILE* key_fp)
{
    int rv = 1;
    uint8_t sk     [32],
            digest [64],
            sig    [64],
            b64_sig[B64_SIG_SIZE];

    if (key_from_file(key_fp, sk) != 0) {
        err("invalid private key");
        goto error;
    }

    uint8_t *buf = malloc(4096);
    if (buf == NULL) {
        err("cannot malloc");
        goto error_2;
    }

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);

    for (;;) {
        size_t n = fread(buf, 1, 1024, fp);
        if (ferror(fp)) {
            err("cannot read");
            goto error_2;
        }
        crypto_blake2b_update(&ctx, buf, n);
        if (_write(stdout, buf, n) != 0) {
            err("cannot write to stdout");
            goto error_2;
        }
        if (feof(fp)) {
            crypto_blake2b_final(&ctx, digest);
            crypto_sign(sig, sk, NULL, digest, 64);
            b64_encode(b64_sig, sig, 64);
            if (_write(stdout, SIG_START, strlen(SIG_START)) != 0
                    || _write(stdout, b64_sig, 44) != 0
                    || _write(stdout, "\n", 1) != 0
                    || _write(stdout, b64_sig + 44, B64_SIG_SIZE - 44) != 0
                    || _write(stdout, SIG_END, strlen(SIG_END)) != 0) {
                err("cannot write to stdout");
                goto error_2;
            }
            rv = 0;
            break;
        }
    }

error_2:
    _free(buf, 1024);
    crypto_wipe((uint8_t *) &ctx, sizeof(ctx));
error:
    crypto_wipe(sk,      32);
    crypto_wipe(digest,  64);
    crypto_wipe(sig,     64);
    crypto_wipe(b64_sig, B64_SIG_SIZE);
    return rv;
}

int check(FILE* fp, FILE* key_fp, int show_id, char* id)
{
    int rv = 1;
    uint8_t pk     [32],
            digest [64],
            sig    [64];

    if (key_from_file(key_fp, pk) != 0) {
        err("invalid public key");
        goto error;
    }

    if (read_signed_file(fp, digest, sig) != 0)
        goto error;

    if (crypto_check(sig, pk, digest, 64) != 0) {
        err("invalid signature");
        goto error;
    }

    if (show_id && printf("%s\n", id) < 0) {
        err("cannot write");
        goto error;
    }
    rv = 0;

error:
    crypto_wipe(pk,     32);
    crypto_wipe(digest, 64);
    crypto_wipe(sig,    64);
    return rv;
}

int check_keyring(FILE* fp, int show_id)
{
    int rv = 1;
    uint8_t pk     [32],
            digest [64],
            sig    [64];
    DIR *dir = NULL;

    if (read_signed_file(fp, digest, sig) != 0)
        goto error;

    char* keyring = getenv("KURV_KEYRING");
    if (keyring == NULL || strlen(keyring) == 0) {
        err("$KURV_KEYRING is not set");
        goto error;
    }

    int dir_fd;
    dir = opendir(keyring);
    if (dir == NULL || (dir_fd = dirfd(dir)) < 0) {
        err("cannot open keyring directory");
        goto error;
    }

    struct dirent *dr = NULL;
    while ((dr = readdir(dir)) != NULL) {
        if (strcmp(dr->d_name, ".") == 0
                || strcmp(dr->d_name, "..") == 0
                || str_endswith(dr->d_name, ".pub") != 0) {
            continue;
        }
        int fd = openat(dir_fd, dr->d_name, O_RDONLY);
        if (fd < 0)
            continue;
        FILE* key_fp = fdopen(fd, "r");
        if (key_fp == NULL) {
            close(fd);
            continue;
        }
        if (key_from_file(key_fp, pk) != 0 /* invalid pk */
                || crypto_check(sig, pk, digest, 64) != 0 /* invalid sig */) {
            fclose(key_fp);
            continue;
        }
        if (show_id
                && printf("%s%s%s\n",
                          keyring,
                          keyring[strlen(keyring) - 1] == '/' ? "" : "/",
                          dr->d_name) < 0) {
            err("cannot write");
            goto error;
        }
        // found it!
        rv = 0;
        fclose(key_fp);
        goto error;
    }

error:
    if (dir != NULL) closedir(dir);
    crypto_wipe(pk,     32);
    crypto_wipe(digest, 64);
    crypto_wipe(sig,    64);
    return rv;
}

int detach(FILE* fp)
{
    int rv = 1;
    size_t start_size = strlen(SIG_START),
           sig_size   = 88 + 1,
           end_size   = strlen(SIG_END),
           total_size = start_size + sig_size + end_size;

    uint8_t sig [64];
    size_t tmp_size = 0;
    uint8_t *buf = malloc(1024),
            *tmp = malloc(1024);
    if (buf == NULL || tmp == NULL) {
        err("malloc");
        goto error;
    }

    for (;;) {
        size_t n = fread(buf, 1, 1024, fp);
        // find signature
        if (feof(fp)) {
            uint8_t *sig_buf;
            if (n >= total_size) {
                if (_write(stdout, tmp, tmp_size) != 0
                        || _write(stdout, buf, n - total_size) != 0) {
                    err("cannot write");
                    goto error;
                }
                sig_buf = buf + n - total_size + start_size;
            } else {
                if (_write(stdout, tmp, tmp_size - (total_size - n)) != 0) {
                    err("cannot write");
                    goto error;
                }
                // sig is now in buf
                memmove(buf + (total_size - n), buf, n);
                memcpy(buf, tmp + tmp_size - (total_size - n), total_size - n);
                sig_buf = buf + start_size;
            }

            if (decode_signature(sig, sig_buf) != 0) {
                err("malformed signature");
                goto error;
            }
            rv = 0;
            break;
        }
        if (ferror(fp)) {
            err("cannot read");
            goto error;
        }
        if (_write(stdout, tmp, tmp_size) != 0) {
            err("cannot write");
            goto error;
        }
        memcpy(tmp, buf, n);
        tmp_size = n;
    }

error:
    _free(buf, 1024);
    _free(tmp, 1024);
    crypto_wipe(sig, 64);
    return rv;
}

int main(int argc, char** argv)
{
    FILE *fp     = NULL;
    FILE *key_fp = NULL;
    char *key_fn = NULL;
    char *base = NULL;
    int check_show_id = 0;
    int expect_fp  = 0;
    int expect_key = 0;
    int action = 0;
    int rv = 1;
    int c;
    while ((c = getopt(argc, argv, "hg:sck:di")) != -1)
        switch (c) {
        default: err("invalid usage. see kurv -h"); goto error;
        case 'h':
            printf("%s", HELP);
            rv = 0;
            goto error;
        case 'k':
            key_fn = optarg;
            key_fp = fopen(key_fn, "r");
            if (key_fp == NULL) {
                err("cannot open key file '%s'", key_fn);
                goto error;
            }
            break;
        case 'i': check_show_id = 1; break;
        case 'g': action = 'g'; base = optarg; break;
        case 's': action = 's'; expect_fp = 1; expect_key = 1; break;
        case 'c': action = 'c'; expect_fp = 1; break;
        case 'd': action = 'd'; expect_fp = 1; break;
        }

    if (expect_key && key_fp == NULL) {
        err("no key specified.");
        goto error;
    }
    if (expect_fp) {
        if (argc == optind) {
            fp = stdin;
        } else if (argc == optind + 1) {
            fp = fopen(argv[optind], "r");
            if (fp == NULL) {
                err("cannot open file '%s'", argv[optind]);
                goto error;
            }
        } else {
            err("invalid usage. see kurv -h");
            goto error;
        }
    }
    switch (action) {
    default:  err("invalid usage. see kurv -h"); break;
    case 'g': rv = generate_keypair(base); break;
    case 's': rv = sign(fp, key_fp); break;
    case 'c': rv = key_fp == NULL
              ? check_keyring(fp, check_show_id)
              : check(fp, key_fp, check_show_id, key_fn); break;
    case 'd': rv = detach(fp); break;
    }

error:
    if (fp     != NULL) fclose(fp);
    if (key_fp != NULL) fclose(key_fp);
    if (fclose(stdout) != 0) {
        err("cannot close stdout");
        rv = 1;
    }
    return rv;
}
