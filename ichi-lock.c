#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "base64/base64.h"
#include "monocypher/monocypher.h"
#include "utils.h"

// +------------+-----------------------------+---------------------------+-------------------------------------+
// | nonce (24) | @ + pubkey (32) + nrecp (1) | mac + enckey (48 * nrecp) | mac + length + mac + enc (34 + ...) |
// +------------+-----------------------------+---------------------------+-------------------------------------+
//              | # + mcost (4) + tcost (1) + salt_length (1) + salt      |
//              +---------------------------------------------------------+

#define B64_KEY_SIZE 44
#define READ_SIZE    32 * 1024 /* 32 KiB */
#define SEE_USAGE    "invalid usage. see -h"

#define WIPE_BUF(buf)    crypto_wipe((buf), sizeof(buf))
#define WIPE_CTX(ctx)    crypto_wipe((ctx), sizeof(*(ctx)))
#define ERR(...)         _err("ichi-lock", __VA_ARGS__)

typedef uint8_t u8;

const u8 HEAD_PUBKEY = '@';
const u8 HEAD_BLOCK  = 'B';
const u8 HEAD_DIGEST = '$';


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
// Lock Stream
//
void increment_nonce(u8 buf[24])
{
    for (size_t i = 0; i < 24 && buf[i] == 255; i++)
        buf[i]++;
}

void ls_lock(u8       *output,  // input_size + 34
             u8        nonce [24],
             const u8  key   [32],
             const u8 *input, size_t input_size)
{
    u8 length[2];
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

int ls_unlock_length(size_t   *to_read,
                     u8        nonce [24],
                     const u8  key   [32],
                     const u8  input [18])
{
    int rv = -1;
    u8 length_buf[2];
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

int ls_unlock_payload(u8       *output,
                      u8        nonce [24],
                      const u8  key   [32],
                      const u8 *input, size_t input_size)
{
    increment_nonce(nonce);
    return crypto_unlock(output,
                         key, nonce,
                         input, /* mac */
                         input + 16, input_size);
}

//
// Encryption
//
// Write encrypted lock stream for fp
int encrypt_lockstream(FILE* fp, const u8 enc_key[32], u8 nonce[24])
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
#define __WRITE(...)  __CHECK(_write(stdout, __VA_ARGS__) == 0, "cannot write")

    int rv = 1;
    size_t pt_size = READ_SIZE + 1,
           ct_size = pt_size + 34;

    u8 *pt = malloc(pt_size),
       *ct = malloc(ct_size);

    __CHECK(pt != NULL && ct != NULL, "malloc");

    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, 64, enc_key, 32);

    while (1) {
        size_t n = fread(pt + 1, 1, pt_size - 1, fp);
        __CHECK(!ferror(fp), "cannot read");
        if (n > 0) {
            pt[0] = HEAD_BLOCK;
            crypto_blake2b_update(&ctx, pt + 1, n);
            ls_lock(ct, nonce, enc_key, pt, 1 + n);
            __WRITE(ct, 34 + 1 + n);
        }
        if (feof(fp)) {
            pt[0] = HEAD_DIGEST;
            crypto_blake2b_final(&ctx, pt + 1);
            ls_lock(ct, nonce, enc_key, pt, 1 + 64);
            __WRITE(ct, 34 + 1 + 64);
            rv = 0;
            break;
        }
    }

error:
    _free(pt, pt_size);
    _free(ct, ct_size);
    WIPE_CTX(&ctx);
    return rv;

#undef __CHECK
#undef __WRITE
}

struct recepients {
    u8*    recp;
    size_t size;
};

int add_recepient(struct recepients *rs, const char* rc)
{
    if (rs->size == 255) {
        ERR("cannot add more than 255 recepients");
        return -1;
    }

    u8 pk_buf[32];
    if (decode_key(pk_buf, (u8 *) rc, strlen(rc)) != 0) {
        ERR("invalid recepient key");
        return -1;
    }

    u8* recp = reallocarray(rs->recp, 32, rs->size + 1);
    if (recp == NULL) {
        if (rs->recp != NULL)
            free(rs->recp);
        ERR("malloc");
        return -1;
    }

    rs->recp = recp;
    memcpy(rs->recp + 32 * rs->size, pk_buf, 32);
    rs->size++;
    return 0;
}

// write key mode for recepients
int encrypt_recepients(u8* nonce,
                       u8* enc_key,
                       u8* sender_sk,
                       struct recepients* rs)
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
#define __WRITE(...)  __CHECK(_write(stdout, __VA_ARGS__) == 0, "cannot write")

    int rv = 1;
    u8 sender_pk     [32],
       nrecp_u8      [1],
       kx_shared_key [32],
       kx_ct         [16 + 32];

    crypto_key_exchange_public_key(sender_pk, sender_sk);
    nrecp_u8[0] = rs->size & 0xFF;

    __WRITE(&HEAD_PUBKEY, 1);
    __WRITE(sender_pk,    32);
    __WRITE(nrecp_u8,     1);

    for (size_t i = 0; i < rs->size; i++) {
        increment_nonce(nonce);
        crypto_key_exchange(kx_shared_key, sender_sk, rs->recp + 32 * i);
        crypto_lock(kx_ct,
                    kx_ct + 16,
                    kx_shared_key,
                    nonce,
                    enc_key, 32);
        __WRITE(kx_ct, sizeof(kx_ct));
    }
    rv = 0;

error:
    WIPE_BUF(sender_pk);
    WIPE_BUF(kx_shared_key);
    WIPE_BUF(kx_ct);
    WIPE_BUF(nrecp_u8);
    return rv;

#undef __CHECK
#undef __WRITE
}

int encrypt(FILE* fp, FILE* key_fp, struct recepients* rs)
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
#define __WRITE(...)  __CHECK(_write(stdout, __VA_ARGS__) == 0, "cannot write")

    int rv = 1;
    u8 nonce         [24],
       sender_sk     [32],
       enc_key       [32];

    __CHECK(_random(nonce,   sizeof(nonce))   == 0, "cannot generate nonce");
    __CHECK(_random(enc_key, sizeof(enc_key)) == 0, "cannot generate encryption key");
    if (read_key(key_fp, sender_sk) != 0)
        goto error;

    __WRITE(nonce, 24);
    if (encrypt_recepients(nonce, enc_key, sender_sk, rs) != 0) goto error;
    if (encrypt_lockstream(fp, enc_key, nonce) != 0) goto error;
    rv = 0;

error:
    WIPE_BUF(nonce);
    WIPE_BUF(sender_sk);
    WIPE_BUF(enc_key);
    return rv;

#undef __WRITE
#undef __CHECK
}

//
// Decryption
//
int decrypt_pubkey_block(FILE* fp,
                         u8* nonce,
                         u8* enc_key,
                         u8* recp_sk,
                         const u8* sender_to_verify)
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
#define __READ(...)   __CHECK(_read(fp, __VA_ARGS__) == 0, "cannot read")

    int rv = 1;
    size_t nrecp;
    u8 kx_ct         [16 + 32],
       kx_shared_key [32],
       sender_pk     [32],
       nrecp_u8      [1];

    __READ(sender_pk, 32);
    __READ(nrecp_u8,  1);
    nrecp = (size_t) nrecp_u8[0];

    if (sender_to_verify != NULL)
        __CHECK(crypto_verify32(sender_to_verify, sender_pk) == 0,
                "sender verification failed");

    crypto_key_exchange(kx_shared_key, recp_sk, sender_pk);

    int found = 0;
    for (; nrecp > 0; nrecp--) {
        increment_nonce(nonce);
        __READ(kx_ct, 48);
        if (!found) {
            // try to unlock chunk
            found = (crypto_unlock(enc_key,
                                   kx_shared_key,
                                   nonce,
                                   kx_ct,
                                   kx_ct + 16, 32) == 0);
        }
    }

    __CHECK(found, "cannot unlock stream");
    rv = 0;

error:
    WIPE_BUF(kx_ct);
    WIPE_BUF(kx_shared_key);
    WIPE_BUF(sender_pk);
    WIPE_BUF(nrecp_u8);
    return rv;

#undef __CHECK
#undef __READ
}

int decrypt(FILE* fp, FILE* key_fp, const u8* verify_sender)
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
#define __READ(...)   __CHECK(_read(fp, __VA_ARGS__) == 0, "cannot read")
#define __WRITE(...)  __CHECK(_write(stdout, __VA_ARGS__) == 0, "cannot write")

    int rv = 1;
    u8 nonce   [24],
       recp_sk [32],
       enc_key [32],
       digest  [64],
       head;
    size_t length;

    size_t buf_size = READ_SIZE + 1 + 16,
           dec_size = READ_SIZE + 1;
    u8 *buf = malloc(buf_size),
       *dec = malloc(dec_size);

    __CHECK(buf != NULL && dec != NULL, "malloc");
    if (read_key(key_fp, recp_sk) != 0)
        goto error;

    __READ(nonce, sizeof(nonce));
    __READ(&head, 1);

    // pubkey mode
    __CHECK(head == HEAD_PUBKEY, "bad encryption");
    if (decrypt_pubkey_block(fp, nonce, enc_key, recp_sk, verify_sender) != 0)
        goto error;

    // begin decrypt
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, sizeof(digest), enc_key, sizeof(enc_key));

    while (1) {
        __READ(buf, 18);
        __CHECK(ls_unlock_length(&length, nonce, enc_key, buf) == 0,
                "bad encryption: cannot unlock");
        __CHECK(length >= 1,             "bad encryption");
        __CHECK(length <= READ_SIZE + 1, "bad encryption");
        __READ(buf, 16 + length);
        __CHECK(ls_unlock_payload(dec, nonce, enc_key, buf, length) == 0,
                "bad encryption: cannot unlock");

        u8 *pt = dec + 1;
        length--;

        switch (dec[0]) {
            case HEAD_BLOCK:
                crypto_blake2b_update(&ctx, pt, length);
                __WRITE(pt, length);
                break;

            case HEAD_DIGEST:
                __CHECK(length == 64, "bad encryption");
                crypto_blake2b_final(&ctx, digest);
                __CHECK(crypto_verify64(digest, pt) == 0,
                        "bad encryption: invalid digest");
                // do 1 extra read and expect an EOF
                __CHECK(fread(buf, 1, 1, fp) != 1 && feof(fp),
                        "bad encryption: expected EOF");
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
    WIPE_BUF(recp_sk);
    WIPE_BUF(enc_key);
    WIPE_BUF(digest);
    return rv;

#undef __CHECK
#undef __READ
#undef __WRITE
}

int main(int argc, char** argv)
{
#define __CHECK(x, m) { if (!(x)) { ERR(m); goto error; } }
    int rv = 1;
    struct recepients rcs;
    rcs.recp = NULL;
    rcs.size = 0;

    FILE* key_fp = NULL;
    u8 verify_sender[32];
    int vflag = 0;

    int expect_key = 0;
    int action = 0;

    int c = 0;
    while ((c = getopt(argc, argv, "EDr:k:v:")) != -1) {
        switch (c) {
        default: goto error;
        case 'r':
            if (add_recepient(&rcs, optarg) != 0)
                goto error;
            break;
        case 'k':
            key_fp = fopen(optarg, "r");
            __CHECK(key_fp != NULL, "cannot open key file");
            break;
        case 'v':
            vflag = 1;
            __CHECK(decode_key(verify_sender, (uint8_t *) optarg, strlen(optarg)) == 0,
                    "invalid public key for verify");
            break;
        case 'E': action = 'E'; expect_key = 1; break;
        case 'D': action = 'D'; expect_key = 1; break;
        }
    }

    __CHECK(!(expect_key && key_fp == NULL), "no key file specified");

    switch (action) {
    case 'E': rv = encrypt(stdin, key_fp, &rcs); break;
    case 'D': rv = decrypt(stdin, key_fp, vflag ? verify_sender : NULL); break;
    }

error:
    if (key_fp != NULL)   fclose(key_fp);
    if (rcs.recp != NULL) free(rcs.recp);
    return rv;

#undef __CHECK
}
