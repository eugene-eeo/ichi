#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "base64/base64.h"
#include "monocypher/monocypher.h"
#include "utils.h"
#include "lock_stream.h"
#include "readpassphrase.h"

// +------------+-----------------------------+---------------------------+-------------------------------------+
// | nonce (24) | @ + pubkey (32) + nrecp (1) | mac + enckey (48 * nrecp) | mac + length + mac + enc (34 + ...) |
// +------------+-----------------------------+---------------------------+-------------------------------------+
//              | # + mcost (4) + tcost (1) + salt_length (1) + salt      |
//              +---------------------------------------------------------+

#define B64_KEY_SIZE 44
#define READ_SIZE    32 * 1024 /* 32 KiB */
#define SEE_USAGE    "invalid usage. see -h"

static const char *HELP =
    "usage:\n"
    "  ichi-lock -E [-k KEY] -r RECP [-o OUTPUT] [INPUT]\n"
    "  ichi-lock -E -p PASS [-o OUTPUT] [INPUT]\n"
    "  ichi-lock -D -k KEY [-v SENDER] [-o OUTPUT] [INPUT]\n"
    "  ichi-lock -D -p PASS [-o OUTPUT] [INPUT]\n"
    "\n"
    "options:\n"
    "  -E        encrypt INPUT into OUTPUT.\n"
    "  -D        decrypt INPUT into OUTPUT.\n"
    "  -k KEY    use secret key file at path KEY.\n"
    "  -r RECP   with -E, specify recepient public key at path RECP.\n"
    "            can be repeated.\n"
    "  -o OUTPUT set OUTPUT stream.\n"
    "  -p PASS   use password file at path PASS.\n"
    "  -a        specify password interactively.\n"
    "  -v SENDER with -D, verify that SENDER produced the encryption.\n"
    "\n"
    "INPUT defaults to stdin, and OUTPUT defaults to stdout.\n"
    "\n"
    "RECP and SENDER should be files produced by `ichi-keygen`.\n\n";

#define WIPE_BUF(buf)    crypto_wipe((buf), sizeof(buf))
#define WIPE_CTX(ctx)    crypto_wipe((ctx), sizeof(*(ctx)))
#define ERR(...)         _err("ichi-lock", __VA_ARGS__)

#define XCHECK(x, ...)   { if (!(x)) { ERR(__VA_ARGS__); goto error; } }
#define XWRITE(...)      XCHECK(_write(__VA_ARGS__) == 0, "cannot write to output stream")
#define XREAD(...)       XCHECK(_read(__VA_ARGS__) == 0,  "cannot read from input stream")

typedef uint8_t u8;

static const u8 HEAD_PUBKEY = '@',
                HEAD_PDKF   = '#',
                HEAD_BLOCK  = 'B',
                HEAD_DIGEST = '$';

struct ls_pdkf_params pdkf_standard_params = {
    .nb_blocks = 100000,
    .nb_iterations = 3,
    .salt_size = 32,
};

//
// Encryption
//
// Write encrypted lock stream for fp
static int encrypt_lockstream(FILE* fp, const u8 enc_key[32], u8 nonce[24])
{
    int rv = 1;
    size_t buf_size = 34 + 1 + READ_SIZE;
    u8 *buf = malloc(buf_size); // mac1 length mac2 head ...

    XCHECK(buf != NULL, "malloc");

    u8 *ct = buf,
       *pt = buf + 34;

    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, enc_key, 32);

    while (1) {
        size_t n = fread(pt + 1, 1, READ_SIZE, fp);
        XCHECK(!ferror(fp), "cannot read");
        if (n > 0) {
            pt[0] = HEAD_BLOCK;
            crypto_blake2b_update(&ctx, pt + 1, n);
            ls_lock(ct, nonce, enc_key, pt, 1 + n);
            XWRITE(stdout, ct, 34 + 1 + n);
        }
        if (feof(fp)) {
            pt[0] = HEAD_DIGEST;
            crypto_blake2b_final(&ctx, pt + 1);
            ls_lock(ct, nonce, enc_key, pt, 1 + 64);
            XWRITE(stdout, ct, 34 + 1 + 64);
            rv = 0;
            break;
        }
    }

error:
    _free(buf, buf_size);
    WIPE_CTX(&ctx);
    return rv;
}

struct recepients {
    u8*    recp;
    size_t size;
};

static int add_recepient(struct recepients *rs, const u8* rcp_key)
{
    if (rs->size == 255) {
        ERR("cannot add more than 255 recepients");
        return -1;
    }

    u8* recp = reallocarray(rs->recp, 32, rs->size + 1);
    if (recp == NULL) {
        ERR("malloc");
        return -1;
    }

    rs->recp = recp;
    memcpy(rs->recp + 32 * rs->size, rcp_key, 32);
    rs->size++;
    return 0;
}

static int encrypt_pdkf(FILE* fp, const u8* password, size_t password_size)
{
    int rv = 1;
    u8 nonce       [24],
       salt        [32],
       pdkf_params [6 + 32],
       enc_key     [32];

    XCHECK(_random(nonce, 24) == 0, "cannot generate nonce");
    XCHECK(_random(salt,  32) == 0, "cannot generate salt");

    ls_pdkf_challenge(pdkf_params, &pdkf_standard_params, salt);
    ls_pdkf_key(enc_key,
                &pdkf_standard_params,
                salt,
                password, password_size);

    XWRITE(stdout, nonce,       24);
    XWRITE(stdout, &HEAD_PDKF,  1);
    XWRITE(stdout, pdkf_params, sizeof(pdkf_params));

    rv = encrypt_lockstream(fp, enc_key, nonce);

error:
    WIPE_BUF(enc_key);
    return rv;
}

static int encrypt_pubkey(FILE* fp, const u8* sk, struct recepients rs)
{
    int rv = 1;
    u8 nonce   [24],
       enc_key [32],
       pk      [32],
       nrecp   [1],
       kx_ct   [32 + 16];

    XCHECK(_random(nonce,   24) == 0, "cannot generate nonce");
    XCHECK(_random(enc_key, 32) == 0, "cannot generate encryption key");

    crypto_key_exchange_public_key(pk, sk);
    nrecp[0] = rs.size & 0xFF;

    XWRITE(stdout, nonce,        24);
    XWRITE(stdout, &HEAD_PUBKEY, 1);
    XWRITE(stdout, pk,           32);
    XWRITE(stdout, nrecp,        1);

    for (size_t i = 0; i < rs.size; i++) {
        ls_kx_challenge(kx_ct,
                        sk,
                        rs.recp + (32 * i),
                        enc_key);
        XWRITE(stdout, kx_ct, sizeof(kx_ct));
    }

    rv = encrypt_lockstream(fp, enc_key, nonce);

error:
    WIPE_BUF(enc_key);
    return rv;
}

//
// Decryption
//
static int decrypt_pubkey_block(FILE* fp,
                                u8* enc_key,
                                const u8* recp_sk,
                                const u8* sender_to_verify)
{
    int rv = 1;
    size_t nrecp;
    u8 kx_ct      [16 + 32],
       shared_key [32],
       sender_pk  [32],
       nrecp_u8   [1];

    XREAD(fp, sender_pk, 32);
    XREAD(fp, nrecp_u8,  1);
    nrecp = (size_t) nrecp_u8[0];

    if (sender_to_verify != NULL)
        XCHECK(crypto_verify32(sender_to_verify, sender_pk) == 0,
              "sender verification failed");

    crypto_key_exchange(shared_key, recp_sk, sender_pk);

    int found = 0;
    for (; nrecp > 0; nrecp--) {
        XREAD(fp, kx_ct, 48);
        // try to unlock chunk
        if (!found)
            found = (ls_kx_unwrap(kx_ct, enc_key, shared_key) == 0);
    }

    XCHECK(found, "cannot unlock stream");
    rv = 0;

error:
    WIPE_BUF(shared_key);
    WIPE_BUF(sender_pk);
    return rv;
}

static int decrypt_pdkf_block(FILE* fp,
                              u8* enc_key,
                              const u8 *password,
                              size_t password_size)
{
    int rv = 1;
    struct ls_pdkf_params params;
    u8 params_buf [6],
       salt       [255];

    XREAD(fp, params_buf, 6);
    ls_pdkf_decode(params_buf, &params);

    XCHECK(ls_pdkf_verify(&params) == 0, "invalid pdkf parameters");
    XREAD(fp, salt, params.salt_size);

    XCHECK(ls_pdkf_key(enc_key,
                       &params,
                       salt,
                       password, password_size) == 0, "cannot derive key");
    rv = 0;

error:
    return rv;
}

static int decrypt(FILE* fp,
                   const u8* sk, const u8* verify_sender,
                   const u8* password, size_t password_size)
{
    int rv = 1;
    u8 nonce    [24],
       enc_key  [32],
       digest   [64],
       key_mode [1];
    size_t length;

    size_t buf_size = READ_SIZE + 1 + 16;
    u8 *buf = malloc(buf_size);

    XCHECK(buf != NULL, "malloc");
    XREAD(fp, nonce, 24);
    XREAD(fp, key_mode, 1);

    switch(key_mode[0]) {
        default:
            ERR("bad encryption");
            goto error;
        case HEAD_PUBKEY:
            XCHECK(sk != NULL, "no secret key given");
            if (decrypt_pubkey_block(fp, enc_key, sk, verify_sender) != 0)
                goto error;
            break;
        case HEAD_PDKF:
            XCHECK(password != NULL, "no password given");
            if (decrypt_pdkf_block(fp, enc_key, password, password_size) != 0)
                goto error;
            break;
    }

    // begin ptrypt
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, enc_key, 32);

    u8 *pt = buf + 16;

    while (1) {
        XREAD(fp, buf, 16 + 2);
        XCHECK(ls_unlock_length(&length, nonce, enc_key, buf) == 0,
               "bad encryption: cannot unlock");
        XCHECK(length >= 1,             "bad encryption");
        XCHECK(length <= READ_SIZE + 1, "bad encryption");
        XREAD(fp, buf, 16 + length);
        XCHECK(ls_unlock_payload(buf + 16, nonce, enc_key, buf, length) == 0,
               "bad encryption: cannot unlock");

        switch (pt[0]) {
        default:
            ERR("bad encryption");
            goto error;
        case HEAD_BLOCK:
            crypto_blake2b_update(&ctx, buf + 17, length - 1);
            XWRITE(stdout, pt + 1, length - 1);
            break;
        case HEAD_DIGEST:
            XCHECK(length == 65, "bad encryption");
            crypto_blake2b_final(&ctx, digest);
            XCHECK(crypto_verify64(digest, pt + 1) == 0, "invalid digest");
            // do 1 extra read and expect an EOF
            XCHECK(fread(buf, 1, 1, fp) == 0 && feof(fp), "expected EOF");
            rv = 0;
            goto error;
        }
    }

error:
    length = 0;
    _free(buf, buf_size);
    WIPE_BUF(enc_key);
    return rv;
}

//
// Helpers for main(...)
//
static int decode_key(u8* out, const u8* buf, size_t bufsize)
{
    int rv = 1;
    if (b64_decoded_size(buf, bufsize) == 32
            && b64_validate(buf, bufsize) == 0) {
        b64_decode(out, buf, bufsize);
        rv = 0;
    }
    return rv;
}

static int read_key(FILE* fp, u8* buf)
{
    int rv = 1;
    u8 b64_buf[B64_KEY_SIZE];
    if (_read(fp, b64_buf, sizeof(b64_buf)) != 0) {
        ERR("cannot read private key");
        goto error;
    }
    if (decode_key(buf, b64_buf, sizeof(b64_buf)) != 0) {
        ERR("invalid private key")
        goto error;
    }
    rv = 0;
error:
    WIPE_BUF(b64_buf);
    return rv;
}

static int askpass(u8* password, size_t bufsize, size_t* password_size)
{
    char* ptr = readpassphrase("ichi-lock: password: ",
                               (char *) password, bufsize,
                               RPP_ECHO_OFF | RPP_REQUIRE_TTY);
    if (ptr == NULL)
        return -1;
    *password_size = strlen((char *) password);
    return 0;
}

int main(int argc, char** argv)
{
    #define XOPEN(fn) {\
        tmp_fp = fopen(fn, "r");\
        XCHECK(tmp_fp != NULL, "fopen '%s'", fn);\
    }

    int rv = 1;
    struct recepients rcs;
    rcs.recp = NULL;
    rcs.size = 0;

    FILE* input_fp = stdin;
    FILE* tmp_fp = NULL;

    size_t password_size = 0;
    u8 verify_sender [32],
       sk            [32],
       password      [512],
       recepient     [32];

    int kflag = 0,
        pflag = 0,
        vflag = 0,
        action = 0;

    int c = 0;
    while ((c = getopt(argc, argv, "hEDr:k:v:p:o:a")) != -1) {
        switch (c) {
        default: goto error;
        case 'h':
            printf("%s", HELP);
            rv = 0;
            goto error;
        case 'r':
            XOPEN(optarg);
            XCHECK(read_key(tmp_fp, recepient) == 0,
                   "invalid recepient key file: %s", optarg);
            _fclose(&tmp_fp);
            if (add_recepient(&rcs, recepient) != 0)
                goto error;
            break;
        case 'k':
            kflag = 1;
            XOPEN(optarg);
            XCHECK(read_key(tmp_fp, sk) == 0,
                   "invalid secret key file: %s", optarg);
            _fclose(&tmp_fp);
            break;
        case 'v':
            vflag = 1;
            XOPEN(optarg);
            XCHECK(read_key(tmp_fp, verify_sender) == 0,
                   "invalid public key file: %s", optarg);
            _fclose(&tmp_fp);
            break;
        case 'a':
            pflag = 1;
            XCHECK(askpass(password, sizeof(password), &password_size) == 0,
                   "askpass failed");
            break;
        case 'p':
            pflag = 1;
            XOPEN(optarg);
            password_size = fread(password, 1, sizeof(password) - 1, tmp_fp);
            password[password_size] = '\0';
            password_size = strcspn((char *) password, "\r\n");
            XCHECK(!ferror(tmp_fp), "cannot read password file: %s", optarg);
            _fclose(&tmp_fp);
            break;
        case 'o':
            stdout = fopen(optarg, "w");
            XCHECK(stdout != NULL, "cannot open output file: %s", optarg);
            break;
        case 'E': action = 'E'; break;
        case 'D': action = 'D'; break;
        }
    }

    // check that we only have at most 1 positional argument
    XCHECK(argc <= optind + 1, SEE_USAGE);
    if (argc == optind + 1) {
        input_fp = fopen(argv[optind], "r");
        XCHECK(input_fp != NULL, "cannot open input file %s", argv[optind]);
    }

    XCHECK(!(kflag && pflag), "cannot specify both key and password");

    switch (action) {
    default:
        ERR(SEE_USAGE);
        break;
    case 'E':
        if (pflag) {
            rv = encrypt_pdkf(input_fp, password, password_size);
        } else {
            XCHECK(rcs.size > 0, "need at least 1 recepient");
            if (!kflag)
                XCHECK(_random(sk, 32) == 0, "cannot generate ephemeral key");
            rv = encrypt_pubkey(input_fp, sk, rcs);
        }
        break;
    case 'D':
        XCHECK(kflag || pflag, "at least one of password or key needs to be specified");
        rv = decrypt(input_fp,
                     kflag ? sk : NULL,
                     vflag ? verify_sender : NULL,
                     pflag ? password : NULL,
                     pflag ? password_size : 0);
        break;
    }

error:
    password_size = 0;
    WIPE_BUF(verify_sender);
    WIPE_BUF(sk);
    WIPE_BUF(password);
    WIPE_BUF(recepient);
    if (input_fp != NULL && fclose(input_fp) != 0) {
        ERR("fclose");
        rv = 1;
    }
    if (stdout != NULL && fclose(stdout) != 0) {
        ERR("fclose");
        rv = 1;
    }
    if (tmp_fp != NULL) fclose(tmp_fp);
    if (rcs.recp != NULL) free(rcs.recp);
    return rv;

    #undef XOPEN
}
