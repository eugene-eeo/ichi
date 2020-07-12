#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "monocypher/monocypher.h"
#include "base64/base64.h"
#include "utils.h"


#define B64_KEY_SIZE 44
#define SEE_USAGE "invalid usage: see ichi-keygen -h"

#define ERR(...)      { _err("ichi-keygen", __VA_ARGS__) }
#define WIPE_BUF(buf) crypto_wipe(buf, sizeof(buf))
#define MAX(a, b)     ((a) > (b) ? (a) : (b))

static const char* HELP =
    "usage: ichi-keygen -h\n"
    "       ichi-keygen {-S | -L} [-p PK] [-s SK] [-b BASE]\n\n"
    "options:\n"
    "  -h       show help.\n"
    "  -S       generate a keypair for ichi-sign.\n"
    "  -L       generate a keypair for ichi-lock.\n"
    "  -p PK    specify public key file (default for -S: .sign.pub, -L: .lock.pub)\n"
    "  -s SK    specify secret key file (default for -S: .sign.key, -L: .lock.key)\n"
    "  -b BASE  write public/secret keys in BASE.pub and BASE.key, respectively.\n\n";


static int keygen_lock(uint8_t pk[32], uint8_t sk[32]);
static int keygen_sign(uint8_t pk[32], uint8_t sk[32]);
static int write_key(uint8_t pk[32],  uint8_t sk[32],
                     char* pk_fn,     char* sk_fn);


int keygen_lock(uint8_t pk[32], uint8_t sk[32])
{
    if (_random(sk, 32) != 0)
        return -1;
    crypto_key_exchange_public_key(pk, sk);
    return 0;
}


int keygen_sign(uint8_t pk[32], uint8_t sk[32])
{
    if (_random(sk, 32) != 0)
        return -1;
    crypto_sign_public_key(pk, sk);
    return 0;
}


int write_key(uint8_t pk[32],  uint8_t sk[32],
              char* pk_fn,     char* sk_fn)
{
    int rv = 1;
    uint8_t b64[B64_KEY_SIZE];
    FILE* fp = NULL;

    // write pk
    b64_encode(b64, pk, 32);
    if ((fp = fopen(pk_fn, "w")) == NULL
            || _write(fp, b64, sizeof(b64)) != 0
            || _write(fp, (uint8_t*) "\n", 1) != 0
            || _fclose(&fp) != 0) {
        ERR("cannot write public key");
        goto error;
    }

    // write sk
    b64_encode(b64, sk, 32);
    if ((fp = fopen(sk_fn, "w")) == NULL
            || _write(fp, b64, sizeof(b64)) != 0
            || _write(fp, (uint8_t*) "\n", 1) != 0
            || _fclose(&fp) != 0) {
        ERR("cannot write secret key");
        goto error;
    }
    rv = 0;

error:
    if (fp != NULL) fclose(fp);
    WIPE_BUF(b64);
    return rv;
}


int main(int argc, char** argv)
{
#define __ERROR(m) { ERR(m); goto error; }

    int rv = 1;
    int c;
    int mode = 0;

    char* base  = NULL;
    char* pk_fn = NULL;
    char* sk_fn = NULL;

    while ((c = getopt(argc, argv, "SLp:s:b:h")) != -1)
        switch (c) {
            default: __ERROR(SEE_USAGE); break;
            case 'S': mode = 'S'; break;
            case 'L': mode = 'L'; break;
            case 'p': pk_fn = optarg; break;
            case 's': sk_fn = optarg; break;
            case 'b': base = optarg; break;
            case 'h':
                printf("%s", HELP);
                rv = 0;
                goto error;
                break;
        }

    if (base != NULL) {
        size_t base_len = strlen(base);
        pk_fn = malloc(base_len + 5);
        sk_fn = malloc(base_len + 5);
        if (pk_fn == NULL || sk_fn == NULL) {
            ERR("malloc");
            goto error;
        }
        memcpy(pk_fn,            base,   base_len);
        memcpy(pk_fn + base_len, ".pub", 5);
        memcpy(sk_fn,            base,   base_len);
        memcpy(sk_fn + base_len, ".key", 5);
    }

    uint8_t pk[32], sk[32];

    switch (mode) {
        default: __ERROR(SEE_USAGE); break;
        case 'S':
            keygen_sign(pk, sk);
            if (pk_fn == NULL) pk_fn = ".sign.pub";
            if (sk_fn == NULL) sk_fn = ".sign.key";
            break;
        case 'L':
            keygen_lock(pk, sk);
            if (pk_fn == NULL) pk_fn = ".lock.pub";
            if (sk_fn == NULL) sk_fn = ".lock.key";
            break;
    }

    rv = write_key(pk, sk,
                   pk_fn,
                   sk_fn);

error:
    WIPE_BUF(pk);
    WIPE_BUF(sk);
    return rv;

#undef __ERROR
}
