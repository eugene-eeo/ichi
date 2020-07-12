#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "base64/base64.h"
#include "monocypher/monocypher.h"
#include "utils.h"
#include "lock_stream.h"

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
    "  -i KEY    use private key file at path KEY.\n"
    "  -r RECP   with -E, specify recepient public key RECP (base64).\n"
    "            can be repeated.\n"
    "  -R FILE   same as -r, but use key at path FILE instead.\n"
    "  -o OUTPUT set OUTPUT stream.\n"
    "  -p PASS   use password file at path PASS.\n"
    "  -v SENDER with -D, verify that SENDER produced the encryption.\n"
    "  -V FILE   same as -v, but use key at path FILE instead.\n"
    "\n"
    "INPUT defaults to stdin, and OUTPUT defaults to stdout.\n"
    "\n"
    "RECP and SENDER should be a base64 string produced by `ichi-keygen`.\n\n"
    ;

#define WIPE_BUF(buf)    crypto_wipe((buf), sizeof(buf))
#define WIPE_CTX(ctx)    crypto_wipe((ctx), sizeof(*(ctx)))
#define ERR(...)         _err("ichi-lock", __VA_ARGS__)

#define XCHECK(x, ...)   { if (!(x)) { ERR(__VA_ARGS__); goto error; } }
#define XWRITE(...)      XCHECK(_write(__VA_ARGS__) == 0, "cannot write to output stream")
#define XREAD(...)       XCHECK(_read(__VA_ARGS__) == 0,  "cannot read from input stream")

typedef uint8_t u8;

const u8 HEAD_PUBKEY = '@';
const u8 HEAD_PDKF   = '#';
const u8 HEAD_BLOCK  = 'B';
const u8 HEAD_DIGEST = '$';

struct ls_pdkf_params pdkf_standard_params = {
    .nb_blocks = 100000,
    .nb_iterations = 3,
    .salt_size = 32,
};

int decode_key(u8* out, const u8* buf, size_t bufsize)
{
    int rv = 1;
    if (b64_decoded_size(buf, bufsize) == 32
            && b64_validate(buf, bufsize) == 0) {
        b64_decode(out, buf, bufsize);
        rv = 0;
    }
    return rv;
}

int read_key(FILE* fp, u8* buf)
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

//
// Encryption
//
// Write encrypted lock stream for fp
int encrypt_lockstream(FILE* fp, const u8 enc_key[32], u8 nonce[24])
{
    int rv = 1;
    size_t pt_size = READ_SIZE + 1,
           ct_size = pt_size + 34;

    u8 *pt = malloc(pt_size),
       *ct = malloc(ct_size);

    XCHECK(pt != NULL && ct != NULL, "malloc");

    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, enc_key, 32);

    while (1) {
        size_t n = fread(pt + 1, 1, pt_size - 1, fp);
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
    _free(pt, pt_size);
    _free(ct, ct_size);
    WIPE_CTX(&ctx);
    return rv;
}

struct recepients {
    u8*    recp;
    size_t size;
};

int add_recepient(struct recepients *rs, const u8* rcp_key)
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

int encrypt_pdkf(FILE* fp, const u8* password, size_t password_size)
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
    WIPE_BUF(nonce);
    WIPE_BUF(salt);
    WIPE_BUF(pdkf_params);
    WIPE_BUF(enc_key);
    return rv;
}

int encrypt_pubkey(FILE* fp, const u8* sk, struct recepients rs)
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
    WIPE_BUF(nonce);
    WIPE_BUF(enc_key);
    WIPE_BUF(pk);
    WIPE_BUF(nrecp);
    WIPE_BUF(kx_ct);
    return rv;
}

//
// Decryption
//
int decrypt_pubkey_block(FILE* fp,
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
    WIPE_BUF(kx_ct);
    WIPE_BUF(shared_key);
    WIPE_BUF(sender_pk);
    WIPE_BUF(nrecp_u8);
    return rv;
}

int decrypt_pdkf_block(FILE* fp,
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
    WIPE_BUF(params_buf);
    WIPE_BUF(salt);
    return rv;
}

int decrypt(FILE* fp,
            const u8* sk, const u8* verify_sender,
            const u8* password, size_t password_size)
{
    int rv = 1;
    u8 nonce   [24],
       enc_key [32],
       digest  [64],
       head;
    size_t length;

    size_t buf_size = READ_SIZE + 1 + 16,
           dec_size = READ_SIZE + 1;
    u8 *buf = malloc(buf_size),
       *dec = malloc(dec_size);

    XCHECK(buf != NULL && dec != NULL, "malloc");
    XREAD(fp, nonce, 24);
    XREAD(fp, &head, 1);

    // pubkey mode
    switch(head) {
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

    // begin decrypt
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, sizeof(digest), enc_key, sizeof(enc_key));

    while (1) {
        XREAD(fp, buf, 18);
        XCHECK(ls_unlock_length(&length, nonce, enc_key, buf) == 0,
               "bad encryption: cannot unlock");
        XCHECK(length >= 1,             "bad encryption");
        XCHECK(length <= READ_SIZE + 1, "bad encryption");
        XREAD(fp, buf, 16 + length);
        XCHECK(ls_unlock_payload(dec, nonce, enc_key, buf, length) == 0,
               "bad encryption: cannot unlock");

        u8 *pt = dec + 1;
        length--;

        switch (dec[0]) {
            case HEAD_BLOCK:
                crypto_blake2b_update(&ctx, pt, length);
                XWRITE(stdout, pt, length);
                break;
            case HEAD_DIGEST:
                XCHECK(length == 64, "bad encryption");
                crypto_blake2b_final(&ctx, digest);
                XCHECK(crypto_verify64(digest, pt) == 0, "invalid digest");
                // do 1 extra read and expect an EOF
                XCHECK(fread(buf, 1, 1, fp) != 1 && feof(fp), "expected EOF");
                rv = 0;
                goto error;
        }
    }

error:
    head = 0;
    length = 0;
    _free(buf, buf_size);
    _free(dec, dec_size);
    WIPE_BUF(nonce);
    WIPE_BUF(enc_key);
    WIPE_BUF(digest);
    return rv;
}

int main(int argc, char** argv)
{
    int rv = 1;
    struct recepients rcs;
    rcs.recp = NULL;
    rcs.size = 0;

    FILE* input_fp = stdin;
    FILE* tmp_fp = NULL;

    size_t password_size = 0;
    u8 verify_sender [32],
       sk            [32],
       password      [1024],
       recepient     [32];

    int kflag = 0,
        pflag = 0,
        vflag = 0,
        action = 0;

    int c = 0;
    while ((c = getopt(argc, argv, "hEDR:r:k:V:v:p:o:")) != -1) {
        switch (c) {
        default: goto error;
        case 'h':
            printf("%s", HELP);
            rv = 0;
            goto error;
        case 'R':
            tmp_fp = fopen(optarg, "r");
            XCHECK(tmp_fp != NULL && read_key(tmp_fp, recepient) == 0,
                   "invalid recepient key file: %s", optarg);
            if (add_recepient(&rcs, recepient) != 0)
                goto error;
            _fclose(&tmp_fp);
            break;
        case 'r':
            XCHECK(decode_key(recepient, (u8 *) optarg, strcspn(optarg, "\r\n")) == 0,
                   "invalid recepient key");
            if (add_recepient(&rcs, recepient) != 0)
                goto error;
            break;
        case 'k':
            kflag = 1;
            tmp_fp = fopen(optarg, "r");
            XCHECK(tmp_fp != NULL && read_key(tmp_fp, sk) == 0,
                   "invalid private key file: %s", optarg);
            _fclose(&tmp_fp);
            break;
        case 'v':
            vflag = 1;
            XCHECK(decode_key(verify_sender, (u8 *) optarg, strlen(optarg)) == 0,
                   "invalid public key for verify");
            break;
        case 'V':
            vflag = 1;
            tmp_fp = fopen(optarg, "r");
            XCHECK(tmp_fp != NULL && read_key(tmp_fp, verify_sender) == 0,
                   "invalid public key for verify: %s", optarg);
            if (add_recepient(&rcs, recepient) != 0)
                goto error;
            _fclose(&tmp_fp);
            break;
        case 'p':
            pflag = 1;
            tmp_fp = fopen(optarg, "r");
            XCHECK(tmp_fp != NULL, "cannot open password file: %s", optarg);
            password_size = fread(password, 1, sizeof(password), tmp_fp);
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

    // check that we only have 1 positional argument at most
    XCHECK(argc <= optind + 1, SEE_USAGE);
    if (argc == optind + 1) {
        input_fp = fopen(argv[optind], "r");
        XCHECK(input_fp != NULL, "cannot open input file %s", argv[optind]);
    }

    XCHECK(kflag || pflag, "at least one of password or key needs to be specified");
    XCHECK(kflag ^  pflag, "cannot specify both -p and -k");

    switch (action) {
    case 'E':
        if (pflag) {
            rv = encrypt_pdkf(input_fp, password, password_size);
        } else {
            XCHECK(kflag, "no key file specified");
            XCHECK(rcs.size > 0, "needs at least 1 recepient");
            rv = encrypt_pubkey(input_fp, sk, rcs);
        }
        break;
    case 'D':
        rv = decrypt(input_fp,
                     kflag ? sk : NULL,
                     vflag ? verify_sender : NULL,
                     pflag ? password : NULL,
                     pflag ? password_size : 0);
        break;
    }

error:
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
}
