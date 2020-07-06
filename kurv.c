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
#include "utils.h"

#define READ_SIZE 4096
#define B64_KEY_SIZE 44  // b64_encoded_size(32)
#define B64_SIG_SIZE 88  // b64_encoded_size(64)
#define SEE_USAGE "invalid usage: see kurv -h"
#define err(...) _err("kurv", __VA_ARGS__)

static const char HELP[] =
    "usage: kurv -h\n"
    "       kurv -g <base>\n"
    "       kurv -d [FILE]\n"
    "       kurv -w -k <key>\n"
    "       kurv -s -k <key> [FILE]\n"
    "       kurv -c [-k <key>] [-i] [FILE]\n"
    "\nargs:\n"
    "  FILE        (signed) file (defaults: stdin)\n"
    "\noptions:\n"
    "  -h          show help page.\n"
    "  -g <base>   generate keypair in <base>.priv and <base>.pub.\n"
    "  -d          print FILE contents without signature.\n"
    "  -k <key>    specify key file for signing / checking.\n"
    "  -w          print pubkey of private key in <key>.\n"
    "  -s          sign FILE using given private key <key>.\n"
    "  -c          check FILE using public key <key>.\n"
    "              if <key> is not specified, try '$KURV_KEYRING/*.pub'\n"
    "              one by one.\n"
    "  -i          print path to public key used on successful check.\n\n"
    ;

static const char SIG_START[] = "\n----BEGIN KURV SIGNATURE----\n";
static const char SIG_END[]   = "\n----END KURV SIGNATURE----\n";
#define START_SIZE (strlen(SIG_START))
#define END_SIZE   (strlen(SIG_END))
#define TOTAL_SIZE (START_SIZE + B64_SIG_SIZE + 1 + END_SIZE)

int generate_keypair(char* base);
int write_pubkey(FILE* key_fp);
int sign(FILE* fp, FILE* key_fp);
int check(FILE* fp, FILE* key_fp, int show_id, char* id);
int check_keyring(FILE* fp, int show_id);
int detach(FILE* fp);

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

// check that buf is valid
int decode_armoured_signature(uint8_t* sig, uint8_t* buf) {
    if (memcmp(buf, SIG_START, START_SIZE) == 0
            && decode_signature(sig, buf + START_SIZE) == 0
            && memcmp(buf + START_SIZE + B64_SIG_SIZE + 1, SIG_END, END_SIZE) == 0) {
        return 0;
    }
    return 1;
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

int str_endswith(char* str, char* suffix)
{
    size_t m = strlen(str),
           n = strlen(suffix);
    if (m < n) return -1;
    return memcmp(str + m - n, suffix, n);
}

int read_signed_file(FILE* fp, uint8_t digest[64], uint8_t sig[64])
{
#define __check(x, m) { if (x) { err(m); goto error; } }

    int rv = 1;
    size_t size = 0;
    uint8_t *buf = malloc(2 * READ_SIZE);
    __check(buf == NULL, "malloc");

    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);

    for (;;) {
        size_t n = fread(buf + size, 1, READ_SIZE, fp);
        size += n;
        __check(ferror(fp), "cannot read");
        if (feof(fp)) {
            // try to find signature in buf
            __check(size < TOTAL_SIZE, "invalid stream");
            __check(decode_armoured_signature(sig, buf + (size - TOTAL_SIZE)) != 0, "malformed signature");
            crypto_blake2b_update(&ctx, buf, size - TOTAL_SIZE);
            crypto_blake2b_final(&ctx, digest);
            return 0;
        }
        if (size > READ_SIZE) {
            crypto_blake2b_update(&ctx, buf, size - READ_SIZE);
            memmove(buf, buf + READ_SIZE, READ_SIZE);
            size -= READ_SIZE;
        }
    }

error:
    _free(buf, 2*READ_SIZE);
    return rv;

#undef __check
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

int write_pubkey(FILE* key_fp)
{
    int rv = 1;
    uint8_t sk     [32],
            pk     [32],
            b64_pk [B64_KEY_SIZE];

    if (key_from_file(key_fp, sk) != 0) {
        err("invalid private key");
        goto error;
    }

    crypto_sign_public_key(pk, sk);
    b64_encode(b64_pk, pk, 32);

    if (_write(stdout, b64_pk, B64_KEY_SIZE) != 0
            || _write(stdout, (uint8_t *) "\n", 1) != 0) {
        err("cannot write");
        goto error;
    }
    rv = 0;

error:
    crypto_wipe(sk, 32);
    crypto_wipe(pk, 32);
    crypto_wipe(b64_pk, B64_KEY_SIZE);
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
        size_t n = fread(buf, 1, READ_SIZE, fp);
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
            if (_write(stdout, (uint8_t*) SIG_START, strlen(SIG_START)) != 0
                    || _write(stdout, b64_sig, 44) != 0
                    || _write(stdout, (uint8_t*) "\n", 1) != 0
                    || _write(stdout, b64_sig + 44, B64_SIG_SIZE - 44) != 0
                    || _write(stdout, (uint8_t*) SIG_END, strlen(SIG_END)) != 0) {
                err("cannot write to stdout");
                goto error_2;
            }
            rv = 0;
            break;
        }
    }

error_2:
    _free(buf, READ_SIZE);
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
#define __check(x, msg) { if (x) { err(msg); goto error; } }

    int rv = 1;
    uint8_t sig [64];
    size_t size = 0;
    uint8_t *buf = malloc(2 * READ_SIZE);
    __check(buf == NULL, "malloc");

    for (;;) {
        size_t n = fread(buf + size, 1, READ_SIZE, fp);
        size += n;
        __check(ferror(fp), "cannot read");
        if (feof(fp)) {
            // try to find signature in buf
            __check(size < TOTAL_SIZE, "invalid stream");
            __check(decode_armoured_signature(sig, buf + (size - TOTAL_SIZE)) != 0, "malformed signature");
            __check(_write(stdout, buf, size - TOTAL_SIZE) != 0, "cannot write to stdout");
            rv = 0;
            break;
        }
        if (size > READ_SIZE) {
            __check(_write(stdout, buf, size - READ_SIZE) != 0, "cannot write to stdout");
            memcpy(buf, buf + READ_SIZE, READ_SIZE);
            size -= READ_SIZE;
        }
    }

error:
    _free(buf, 2 * READ_SIZE);
    crypto_wipe(sig, 64);
    return rv;

#undef __check
}

int main(int argc, char** argv)
{
#define __error(...) { err(__VA_ARGS__); goto error; }
#define __setaction(a) { if (action != 0) { __error("invalid usage. see kurv -h"); } action = a; }

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
    while ((c = getopt(argc, argv, "hg:wsck:di")) != -1)
        switch (c) {
            default: __error("invalid usage. see kurv -h");
            case 'h':
                printf("%s", HELP);
                rv = 0;
                goto error;
            case 'k':
                key_fn = optarg;
                key_fp = fopen(key_fn, "r");
                if (key_fp == NULL)
                    __error("cannot open key file '%s'", key_fn);
                break;
            case 'i': check_show_id = 1; break;
            case 'g': __setaction('g'); base = optarg; break;
            case 'w': __setaction('w'); expect_key = 1; break;
            case 's': __setaction('s'); expect_fp = 1; expect_key = 1; break;
            case 'c': __setaction('c'); expect_fp = 1; break;
            case 'd': __setaction('d'); expect_fp = 1; break;
        }

    if (expect_key && key_fp == NULL) __error("no key specified.");
    if (!expect_fp && argc > optind)  __error("invalid usage. see kurv -h");
    if (expect_fp) {
        if (argc == optind) {
            fp = stdin;
        } else if (argc == optind + 1) {
            fp = fopen(argv[optind], "r");
            if (fp == NULL)
                __error("cannot open file '%s'", argv[optind]);
        } else {
            __error("invalid usage. see kurv -h");
        }
    }
    switch (action) {
        default:  __error("invalid usage. see kurv -h"); break;
        case 'g': rv = generate_keypair(base); break;
        case 's': rv = sign(fp, key_fp); break;
        case 'c': rv = key_fp == NULL
                  ? check_keyring(fp, check_show_id)
                  : check(fp, key_fp, check_show_id, key_fn); break;
        case 'd': rv = detach(fp); break;
        case 'w': rv = write_pubkey(key_fp); break;
    }

error:
    if (fp     != NULL) fclose(fp);
    if (key_fp != NULL) fclose(key_fp);
    if (fclose(stdout) != 0) {
        err("cannot close stdout");
        rv = 1;
    }
    return rv;

#undef __error
#undef __setaction
}
