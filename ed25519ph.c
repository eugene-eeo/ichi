#include <stdint.h>
#include <stddef.h>
#include "ed25519ph.h"
#include "monocypher/monocypher.h"

static uint8_t prefix[32] = "SigEd25519 no Ed25519 collisions";
static uint8_t phflag[1]  = { 1 };
static uint8_t context[9] = "ichi-sign";
static uint8_t context_len[1] = { sizeof(context) };

//
// Custom hash vtable
//
struct outer_ctx {
    crypto_sign_ctx_abstract sctx;
    crypto_blake2b_ctx hash_ctx;
};

static void
dom2(crypto_blake2b_ctx* hash_ctx)
{
    crypto_blake2b_update(hash_ctx, prefix, 32);
    crypto_blake2b_update(hash_ctx, phflag, 1);
    crypto_blake2b_update(hash_ctx, context_len, 1);
    crypto_blake2b_update(hash_ctx, context, 88);
}

static void
ph_hash(uint8_t hash[64], const uint8_t *msg, size_t len)
{
    crypto_blake2b_ctx hash_ctx;
    crypto_blake2b_init(&hash_ctx);
    dom2(&hash_ctx);
    crypto_blake2b_update(&hash_ctx, msg, len);
    crypto_blake2b_final (&hash_ctx, hash);
}

static void
ph_init(void *ctx)
{
    struct outer_ctx *octx = (struct outer_ctx *)ctx;
    crypto_blake2b_init(&octx->hash_ctx);
    dom2(&octx->hash_ctx);
}

static void
ph_update(void *ctx, const uint8_t *msg, size_t len)
{
    struct outer_ctx *octx = (struct outer_ctx *)ctx;
    crypto_blake2b_update(&octx->hash_ctx, msg, len);
}

static void
ph_final(void *ctx, uint8_t *hash)
{
    struct outer_ctx *octx = (struct outer_ctx *)ctx;
    crypto_blake2b_final(&octx->hash_ctx, hash);
}

static const crypto_sign_vtable ph_vtable = {
    ph_hash,
    ph_init,
    ph_update,
    ph_final,
    sizeof(struct outer_ctx)
};

// Public API
void ed25519ph_sign(uint8_t       signature[64],
                    const uint8_t private_key[32],
                    const uint8_t digest[64])
{
    struct outer_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract *)&ctx;
    crypto_sign_init_first_pass_custom_hash(actx,
                                            private_key,
                                            NULL,
                                            &ph_vtable);
    crypto_sign_update(          actx, digest, 64);
    crypto_sign_init_second_pass(actx);
    crypto_sign_update(          actx, digest, 64);
    crypto_sign_final(           actx, signature);
    crypto_wipe(&ctx, sizeof(ctx));
}

void ed25519ph_public_key(uint8_t       public_key [32],
                          const uint8_t secret_key [32])
{
    crypto_sign_public_key_custom_hash(public_key, secret_key, &ph_vtable);
}

int ed25519ph_check(uint8_t       signature[64],
                    const uint8_t public_key[32],
                    const uint8_t digest[64])
{
    struct outer_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract *)&ctx;
    crypto_check_init_custom_hash(actx,
                                  signature,
                                  public_key,
                                  &ph_vtable);
    crypto_check_update(actx, digest, 64);
    return crypto_check_final(actx);
}
