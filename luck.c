#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>

#include "monocypher/monocypher.h"
#include "readpassphrase.h"
#include "utils.h"

#define ERR(...)          _err("luck", __VA_ARGS__)
#define WIPE_CTX(ctx)     crypto_wipe(ctx, sizeof(*(ctx)))
#define WIPE_BUF(buffer)  crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)         ((a) > (b) ? (b) : (a))

#define PDKF_BUFSIZE 256
#define PDKF_MCOST 100000
#define PDKF_TCOST 3

static const char* SEE_HELP = "invalid usage: see luck -h";
static const char* HELP =
    "usage: luck -h\n"
    "       luck -g <base>\n"
    "       luck -w -k <key>\n"
    "       luck {-e|-d} {-k <key> | -p} [FILE]\n\n"
    "FILE defaults to stdin if no FILE is specified.\n\n"
    "options:\n"
    "  -h         show help.\n"
    "  -g <base>  generate keypair in <key>.sk (secret) and <key>.pk (public).\n"
    "  -k <key>   specify secret/public key file.\n"
    "  -w         print public key for secret key <key>.\n"
    "  -e         encrypt FILE, using key-exchange or password mode.\n"
    "  -d         decrypt FILE, similar to -e.\n"
    "  -p         use $LUCK_ASKPASS to ask for password.\n"
    "examples:\n"
    "  -ek id.pk  encrypts the stream, can only be opened by 'id.sk'.\n"
    "  -dk id.sk  decrypts the above.\n";

static const uint8_t HEAD_PUBKEY = '@';
static const uint8_t HEAD_PDKF   = '#';
static const uint8_t HEAD_BLOCK  = 'b';
static const uint8_t HEAD_DIGEST = '$';

int generate_keypair(char *base);
int write_pubkey(FILE *key_fp);
int encrypt(FILE *fp, FILE *key_fp, uint8_t *password, size_t password_size);
int decrypt(FILE *fp, FILE *key_fp, uint8_t *password, size_t password_size);

//
// Lock Stream
//
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
    WIPE_BUF(length);
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
    *to_read = (size_t) length_buf[0]
             | (size_t) length_buf[1] << 8;
error:
    WIPE_BUF(length_buf);
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

//
// PDKF Block
//
void pdkf_encode_params(uint8_t* out,
                        const size_t nb_blocks, const size_t nb_iterations,
                        const uint8_t* salt, const size_t salt_size)
{
    // uint8_t out[salt_size + 6]
    out[0] = (nb_blocks)       & 0xFF;
    out[1] = (nb_blocks >> 8)  & 0xFF;
    out[2] = (nb_blocks >> 16) & 0xFF;
    out[3] = (nb_blocks >> 24) & 0xFF;
    out[4] = (nb_iterations)   & 0xFF;
    out[5] = (salt_size)       & 0xFF;
    memcpy(out + 6, salt, salt_size);
}

void pdkf_decode_params(uint8_t* buf,
                        size_t* nb_blocks, size_t* nb_iterations,
                        size_t* salt_size)
{
    *nb_blocks = (size_t) buf[0]
               | (size_t) buf[1] << 8
               | (size_t) buf[2] << 16
               | (size_t) buf[3] << 24;
    *nb_iterations = (size_t) buf[4];
    *salt_size     = (size_t) buf[5];
}

int pdkf_key(uint8_t *key,
             size_t nb_blocks, size_t nb_iterations,
             uint8_t* password, size_t password_size,
             uint8_t* salt, size_t salt_size)
{
    void* work_area = malloc(1024 * nb_blocks);
    if (work_area == NULL)
        return -1;

    crypto_argon2i(key, 32,
                   work_area, nb_blocks, nb_iterations,
                   password, password_size,
                   salt, salt_size);
    free(work_area);
    return 0;
}

//
// PDKF Askpass support
//
int pdkf_askpass(char* buf, size_t bufsize)
{
    int rv = 1;
    char *prog = getenv("LUCK_ASKPASS");
    if (prog == NULL) {
        // try using readpassphrase
        if (readpassphrase("luck password: ", buf, bufsize, RPP_REQUIRE_TTY) == NULL)
            goto error;
        return 0;
    }

    FILE *fp = popen(prog, "r");
    if (fp == NULL)
        goto error;

    (void) fread(buf, 1, bufsize - 1, fp);
    if (ferror(fp)) goto error;
    if (pclose(fp) != 0)
        goto error;

    buf[bufsize-1] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
    rv = 0;
error:
    return rv;
}

int generate_keypair(char *base)
{
    int rv = 1;
    uint8_t sk[32],
            pk[32];

    if (getrandom(sk, sizeof(sk), 0) < 0) {
        ERR("cannot generate keypair");
        goto error_1;
    }

    crypto_key_exchange_public_key(pk, sk);

    size_t len = strlen(base);
    FILE* fp;
    char* fn = malloc(len + 4);
    if (fn == NULL) {
        ERR("cannot malloc");
        goto error_1;
    }

    // Secret key
    memcpy(fn, base, len);
    memcpy(fn + len, ".sk", 3);
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(sk, 1, sizeof(sk), fp) != sizeof(sk)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        ERR("cannot write secret key in '%s'", fn);
        goto error_2;
    }

    // Public key
    memcpy(fn + len, ".pk", 3);
    fp = fopen(fn, "w");
    if (fp == NULL
            || fwrite(pk, 1, sizeof(pk), fp) != sizeof(pk)
            || fwrite("\n", 1, 1, fp) != 1
            || _fclose(&fp) != 0) {
        ERR("cannot write public key in '%s'", fn);
        goto error_2;
    }

    rv = 0;

error_2:
    if (fp != NULL)
        fclose(fp);
    _free(fn, len + 4);
error_1:
    WIPE_BUF(sk);
    WIPE_BUF(pk);
    return rv;
}

int write_pubkey(FILE* fp)
{
    int rv = 1;
    uint8_t sk[32],
            pk[32];

    if (_read(fp, sk, 32) != 0) {
        ERR("invalid secret key");
        goto error;
    }

    crypto_key_exchange_public_key(pk, sk);

    if (_write(stdout, pk, sizeof(pk)) != 0
            || _write(stdout, (uint8_t *) "\n", 1) != 0) {
        ERR("cannot write");
        goto error;
    }
    rv = 0;

error:
    WIPE_BUF(sk);
    WIPE_BUF(pk);
    return rv;
}

int _encrypt(FILE* fp, uint8_t *key)
{
#define __ERROR(m)       { ERR(m); goto error; }
#define __CHECK_WRITE(x) { if ((x) != 0) __ERROR("cannot write"); }

    int rv = 1;
    size_t raw_buf_size = 4096,
           enc_buf_size = 4096 + 34;

    uint8_t *raw_buf = malloc(raw_buf_size),
            *enc_buf = malloc(enc_buf_size);
    if (raw_buf == NULL || enc_buf == NULL)
        __ERROR("cannot malloc");

    uint8_t nonce[24] = { 0 };
    uint8_t digest[64];

    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, key, 32);

    size_t n;
    for (;;) {
        n = fread(raw_buf, 1, raw_buf_size, fp);
        if (ferror(fp))
            __ERROR("cannot read");
        if (n > 0) {
            crypto_blake2b_update(&ctx, raw_buf, n);
            ls_lock(enc_buf,
                    nonce,
                    key,
                    raw_buf, n);
            __CHECK_WRITE(_write(stdout, &HEAD_BLOCK, 1));
            __CHECK_WRITE(_write(stdout, enc_buf, n + 34));
        }
        if (feof(fp)) {
            crypto_blake2b_final(&ctx, digest);
            __CHECK_WRITE(_write(stdout, &HEAD_DIGEST, 1));
            __CHECK_WRITE(_write(stdout, digest, 64));
            rv = 0;
            break;
        }
    }

error:
    _free(enc_buf, enc_buf_size);
    _free(raw_buf, raw_buf_size);
    WIPE_BUF(digest);
    WIPE_BUF(nonce);
    WIPE_CTX(&ctx);
    return rv;

#undef __ERROR
#undef __CHECK_WRITE
}

int encrypt(FILE* fp, FILE* key_fp, uint8_t* password, size_t password_size)
{
#define __ERROR(m)       { ERR(m); goto error; }
#define __CHECK_WRITE(x) { if ((x) != 0) __ERROR("cannot write"); }

    int rv = 1;
    uint8_t eph_sk     [32],
            eph_pk     [32],
            pk         [32],
            shared_key [32],
            pdkf_out   [32 + 6];

    if (getrandom(eph_sk, sizeof(eph_sk), 0) < 0)
        __ERROR("cannot generate random key");

    if (key_fp != NULL) {
        if (_read(key_fp, pk, 32) != 0)
            __ERROR("invalid public key");

        crypto_key_exchange_public_key(eph_pk, eph_sk);
        crypto_key_exchange(shared_key, eph_sk, pk);

        __CHECK_WRITE(_write(stdout, &HEAD_PUBKEY, 1));
        __CHECK_WRITE(_write(stdout, eph_pk, sizeof(eph_pk)));
    } else {
        // use eph_sk as salt
        pdkf_encode_params(pdkf_out, PDKF_MCOST, PDKF_TCOST, eph_sk, 32);
        pdkf_key(shared_key, PDKF_MCOST, PDKF_TCOST,
                 password, password_size,
                 eph_sk, 32);

        __CHECK_WRITE(_write(stdout, &HEAD_PDKF, 1));
        __CHECK_WRITE(_write(stdout, pdkf_out, sizeof(pdkf_out)));
    }

    rv = _encrypt(fp, shared_key);

error:
    WIPE_BUF(pdkf_out);
    WIPE_BUF(shared_key);
    WIPE_BUF(eph_sk);
    WIPE_BUF(eph_pk);
    WIPE_BUF(pk);
    return rv;

#undef __ERROR
#undef __CHECK_WRITE
}

int decrypt(FILE* fp, FILE* key_fp, uint8_t* password, size_t password_size)
{
#define __ERROR(m)        { ERR(m); goto error; }
#define __CHECK_WRITE(x)  { if ((x) != 0) __ERROR("cannot write"); }
#define __CHECK_READ(x)   { if ((x) != 0) __ERROR("bad encryption: cannot read"); }
#define __CHECK_UNLOCK(x) { if ((x) != 0) __ERROR("bad encryption: cannot unlock"); }

    int rv = 1;
    uint8_t eph_pk      [32],
            sk          [32],
            shared_key  [32],
            pdkf_params [6],
            pdkf_salt   [255];

    size_t raw_buf_size = 4096 + 34,
           dec_buf_size = 4096;
    uint8_t *raw_buf = malloc(raw_buf_size),
            *dec_buf = malloc(dec_buf_size);
    if (raw_buf == NULL || dec_buf == NULL)
        __ERROR("malloc failed");

    uint8_t nonce[24] = { 0 };
    uint8_t digest[64];
    uint8_t head;
    size_t length; // length of each BLOCK chunk
    crypto_blake2b_ctx ctx;

    // determine key mode
    __CHECK_READ(_read(fp, &head, 1));
    switch (head) {
        default: __ERROR("bad encryption");
        case HEAD_PDKF:
        {
            size_t nb_blocks,
                   nb_iterations,
                   salt_size;
            __CHECK_READ(_read(fp, pdkf_params, 6));
            pdkf_decode_params(pdkf_params, &nb_blocks, &nb_iterations, &salt_size);
            __CHECK_READ(_read(fp, pdkf_salt, salt_size));
            pdkf_key(shared_key,
                     nb_blocks, nb_iterations,
                     password, password_size,
                     pdkf_salt, salt_size);
            break;
        }
        case HEAD_PUBKEY:
        {
            __CHECK_READ(_read(fp, eph_pk, 32));
            if (key_fp == NULL)
                __ERROR("no secret key specified");
            if (_read(key_fp, sk, 32) != 0)
                __ERROR("invalid secret key");
            crypto_key_exchange(shared_key, sk, eph_pk);
            break;
        }
    }

    crypto_blake2b_general_init(&ctx, 64, shared_key, 32);

    int done = 0;
    while (!done) {
        // read head byte
        __CHECK_READ(_read(fp, &head, 1));
        switch (head) {
            default: __ERROR("bad encryption");
            case HEAD_BLOCK:
            {
                __CHECK_READ(  _read(fp, raw_buf, 18));
                __CHECK_UNLOCK(ls_unlock_length(&length, nonce, shared_key, raw_buf));
                if (length == 0 || length > 4096)
                    __ERROR("bad encryption");
                __CHECK_READ(  _read(fp, raw_buf, length + 16));
                __CHECK_UNLOCK(ls_unlock_payload(dec_buf, nonce, shared_key, raw_buf, length));
                __CHECK_WRITE( _write(stdout, dec_buf, length));
                crypto_blake2b_update(&ctx, dec_buf, length);
                break;
            }
            case HEAD_DIGEST:
            {
                crypto_blake2b_final(&ctx, digest);
                __CHECK_READ(_read(fp, raw_buf, 64));
                if (crypto_verify64(digest, raw_buf) != 0)
                    __ERROR("digest doesn't match");
                // expect EOF - do one extra read here otherwise we cannot
                // detect EOF.
                if (fread(raw_buf, 1, 1, fp) == 1 || !feof(fp))
                    __ERROR("expected EOF");
                done = 1;
                rv = 0;
                break;
            }
        }
    }

error:
    _free(raw_buf, raw_buf_size);
    _free(dec_buf, dec_buf_size);
    length = 0;
    head = 0;
    WIPE_CTX(&ctx);
    WIPE_BUF(nonce);
    WIPE_BUF(eph_pk);
    WIPE_BUF(sk);
    WIPE_BUF(shared_key);
    WIPE_BUF(digest);
    return rv;

#undef __ERROR
#undef __CHECK_WRITE
#undef __CHECK_READ
#undef __CHECK_UNLOCK
}

int main(int argc, char** argv)
{
#define __ERROR(...) { ERR(__VA_ARGS__); goto out; }
#define __SETACTION(a) { if (action != 0) { __ERROR("%s", SEE_HELP); } action = a; }

    int rv = 1;
    FILE* fp     = NULL;
    FILE* key_fp = NULL;
    char* base = NULL;

    uint8_t password[PDKF_BUFSIZE];
    size_t password_size;
    int askpass = 0;

    int action = 0;
    int c;
    int expect_fp  = 0;
    int expect_key = 0;
    int expect_key_or_password = 0;

    while ((c = getopt(argc, argv, "hg:wedk:p")) != -1)
        switch (c) {
            default: ERR("%s", SEE_HELP); goto out;
            case 'h':
                printf("%s", HELP);
                rv = 0;
                goto out;
            case 'g': __SETACTION('g'); base = optarg;  break;
            case 'w': __SETACTION('w'); expect_key = 1; break;
            case 'e': __SETACTION('e'); expect_fp = 1; expect_key_or_password = 1; break;
            case 'd': __SETACTION('d'); expect_fp = 1; expect_key_or_password = 1; break;
            case 'p': askpass = 1; break;
            case 'k':
                key_fp = fopen(optarg, "r");
                if (key_fp == NULL)
                    __ERROR("cannot open key file '%s'", optarg);
                break;
        }

    if (key_fp != NULL && askpass)    __ERROR("can only specify one of password or key");
    if (expect_key && key_fp == NULL) __ERROR("no key specified");
    if (!expect_fp && argc > optind)  __ERROR("%s", SEE_HELP);
    if (expect_fp) {
        if (argc == optind + 1) {
            fp = fopen(argv[optind], "r");
            if (fp == NULL)
                __ERROR("cannot open '%s'", argv[optind]);
        } else if (argc == optind) {
            fp = stdin;
        } else {
            __ERROR("%s", SEE_HELP);
        }
    }
    if (expect_key_or_password && key_fp == NULL && !askpass)
        __ERROR("expected key or password");
    if (expect_key_or_password && askpass) {
        if (pdkf_askpass((char *) password, sizeof(password)) != 0)
            __ERROR("askpass failed");
        password_size = strlen((char *) password);
    }

    switch (action) {
        default:  __ERROR("%s", SEE_HELP);     break;
        case 'g': rv = generate_keypair(base); break;
        case 'w': rv = write_pubkey(key_fp);   break;
        case 'e': rv = encrypt(fp, key_fp, password, password_size); break;
        case 'd': rv = decrypt(fp, key_fp, password, password_size); break;
    }

out:
    WIPE_BUF(password);
    if (fp     != NULL) fclose(fp);
    if (key_fp != NULL) fclose(key_fp);
    if (fclose(stdout) != 0) {
        ERR("cannot close stdout");
        rv = 1;
    }
    return rv;

#undef __ERROR
#undef __SETACTION
}
