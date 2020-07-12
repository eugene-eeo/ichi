#ifndef LOCK_STREAM_H
#define LOCK_STREAM_H

#include <stdint.h>
#include <stddef.h>

void ls_increment_nonce(uint8_t buf[24]);

struct ls_pdkf_params {
    size_t nb_blocks;
    size_t nb_iterations;
    size_t salt_size;
};

//
// Encryption
//
// KX Mode
void ls_kx_challenge(uint8_t       output[16 + 32],
                     const uint8_t sk[32],
                     const uint8_t pk[32],
                     const uint8_t enc_key[32]);
// PDKF Mode
void ls_pdkf_challenge(uint8_t *out /* 6 + salt_size */,
                       const struct ls_pdkf_params *params,
                       const uint8_t *salt);
// Lockstream
void ls_lock(uint8_t       *output,  // input_size + 34
             uint8_t        nonce [24],
             const uint8_t  key   [32],
             const uint8_t *input, size_t input_size);


//
// PDKF
//
int ls_pdkf_key(uint8_t key[32],
                const struct ls_pdkf_params *params,
                const uint8_t *salt,
                const uint8_t *password, size_t password_size);


//
// Decryption
//
// KX Mode
int ls_kx_unwrap(uint8_t       input[16 + 32],
                 uint8_t       enc_key[32],
                 const uint8_t shared_key[32]);
// PDKF
void ls_pdkf_decode(uint8_t input[6],
                    struct ls_pdkf_params *params);
int ls_pdkf_verify(const struct ls_pdkf_params *params);

// Lockstream
int ls_unlock_length(size_t       *to_read,
                     uint8_t       nonce [24],
                     const uint8_t key   [32],
                     const uint8_t input [18]);

int ls_unlock_payload(uint8_t       *output,
                      uint8_t        nonce [24],
                      const uint8_t  key   [32],
                      const uint8_t *input, size_t input_size);
#endif
