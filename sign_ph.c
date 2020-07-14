#include <stdint.h>
#include <stddef.h>
#include "sign_ph.h"
#include "monocypher/monocypher.h"

typedef uint8_t u8;
static const u8 prefix[32] = "SigEd25519 no Ed25519 collisions";
static const u8 phflag[1]  = { 1 };
static const u8 context[9] = "ichi-sign";
static const u8 context_len[1] = { sizeof(context) };

//
// Custom hash vtable
//
typedef struct ph_ctx {
    crypto_sign_ctx_abstract ctx;
    crypto_blake2b_ctx       hash;
} ph_ctx;

static void
ph_dom2(crypto_blake2b_ctx* hash)
{
    crypto_blake2b_update(hash, prefix, 32);
    crypto_blake2b_update(hash, phflag, 1);
    crypto_blake2b_update(hash, context_len, 1);
    crypto_blake2b_update(hash, context, sizeof(context));
}

static void
ph_hash(u8 digest[64], const u8 *msg, size_t len)
{
    crypto_blake2b_ctx hash;
    crypto_blake2b_init  (&hash);
    ph_dom2              (&hash);
    crypto_blake2b_update(&hash, msg, len);
    crypto_blake2b_final (&hash, digest);
}

static void
ph_init(void *ctx)
{
    ph_ctx *octx = (ph_ctx *)ctx;
    crypto_blake2b_init(&octx->hash);
    ph_dom2            (&octx->hash);
}

static void
ph_update(void *ctx, const u8 *msg, size_t len)
{
    ph_ctx *octx = (ph_ctx *)ctx;
    crypto_blake2b_update(&octx->hash, msg, len);
}

static void
ph_final(void *ctx, u8 *digest)
{
    ph_ctx *octx = (ph_ctx *)ctx;
    crypto_blake2b_final(&octx->hash, digest);
}

static const crypto_sign_vtable ph_vtable = {
    ph_hash,
    ph_init,
    ph_update,
    ph_final,
    sizeof(struct ph_ctx),
};


//
// Public API
//
void sign_ph_sign(u8       signature   [64],
                  const u8 private_key [32],
                  const u8 digest      [64])
{
    ph_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract *)&ctx;
    crypto_sign_init_first_pass_custom_hash(actx,
                                            private_key,
                                            NULL,
                                            &ph_vtable);
    crypto_sign_update          (actx, digest, 64);
    crypto_sign_init_second_pass(actx);
    crypto_sign_update          (actx, digest, 64);
    crypto_sign_final           (actx, signature);
}

void sign_ph_public_key(u8       public_key [32],
                        const u8 secret_key [32])
{
    crypto_sign_public_key_custom_hash(public_key, secret_key,
                                       &ph_vtable);
}

int sign_ph_check(u8       signature  [64],
                  const u8 public_key [32],
                  const u8 digest     [64])
{
    ph_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract *)&ctx;
    crypto_check_init_custom_hash(actx,
                                  signature,
                                  public_key,
                                  &ph_vtable);
    crypto_check_update(actx, digest, 64);
    return crypto_check_final(actx);
}
