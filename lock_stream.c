#include <stdlib.h>
#include <string.h>
#include "lock_stream.h"
#include "monocypher/monocypher.h"

#define WIPE_BUF(buf) crypto_wipe((buf), sizeof(buf))

typedef uint8_t u8;

static const u8 zeros [24] = { 0 };

void ls_increment_nonce(u8 buf[24])
{
    for (size_t i = 0; i < 24 && buf[i] == 255; i++)
        buf[i]++;
}

//
// KX Key mode
//
void ls_kx_challenge(      u8 output[16 + 32],
                     const u8 sk[32],
                     const u8 pk[32],
                     const u8 enc_key[32])
{
    u8 shared_key[32];
    crypto_key_exchange(shared_key, sk, pk);
    crypto_lock(output,
                output + 16,
                shared_key,
                zeros,
                enc_key, 32);
    WIPE_BUF(shared_key);
}

int ls_kx_unwrap(      u8 input[16 + 32],
                       u8 enc_key[32],
                 const u8 shared_key[32])
{
    return crypto_unlock(enc_key,
                         shared_key,
                         zeros,
                         input,
                         input + 16, 32);
}


//
// PDKF Key Mode
//
void ls_pdkf_challenge(u8 *out,
                       const struct ls_pdkf_params *params,
                       const u8 *salt)
{
    out[0] = (params->nb_blocks)       & 0xFF;
    out[1] = (params->nb_blocks >> 8)  & 0xFF;
    out[2] = (params->nb_blocks >> 16) & 0xFF;
    out[3] = (params->nb_blocks >> 24) & 0xFF;
    out[4] = (params->nb_iterations)   & 0xFF;
    out[5] = (params->salt_size)       & 0xFF;
    memcpy(out + 6, salt, params->salt_size);
}

int ls_pdkf_key(u8 key[32],
                const struct ls_pdkf_params *params,
                const u8 *salt,
                const u8 *password, size_t password_size)
{
    void* work_area = malloc(params->nb_blocks * 1024);
    if (work_area == NULL)
        return -1;

    crypto_argon2i(key, 32,
                   work_area, params->nb_blocks, params->nb_iterations,
                   password, password_size,
                   salt, params->salt_size);
    free(work_area);
    return 0;
}

void ls_pdkf_decode(u8 *input, struct ls_pdkf_params *params)
{
    params->nb_blocks = (size_t) input[0]
                      | (size_t) input[1] << 8
                      | (size_t) input[2] << 16
                      | (size_t) input[3] << 24;
    params->nb_iterations = (size_t) input[4];
    params->salt_size     = (size_t) input[5];
}

int ls_pdkf_verify(const struct ls_pdkf_params *params)
{
    if (!(params->nb_blocks >= 8
                && params->nb_blocks <= 100000
                && params->nb_iterations >= 1
                && params->nb_iterations <= 10
                && params->salt_size >= 8)) {
        return -1;
    }
    return 0;
}


//
// After key mode (lock stream)
//
void ls_lock(u8       *output,  // input_size + 34
             u8        nonce [24],
             const u8  key   [32],
             const u8 *input, size_t input_size)
{
    u8 length[2];
    length[0] = (input_size)      & 0xFF;
    length[1] = (input_size >> 8) & 0xFF;

    ls_increment_nonce(nonce);
    crypto_lock(output,
                output + 16, /* mac */
                key, nonce,
                length, 2);

    ls_increment_nonce(nonce);
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
    ls_increment_nonce(nonce);
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
    ls_increment_nonce(nonce);
    return crypto_unlock(output,
                         key, nonce,
                         input, /* mac */
                         input + 16, input_size);
}
