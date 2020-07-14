#ifndef ED25519PH_H
#define ED25519PH_H

#include <stdint.h>
#include <stddef.h>

void ed25519ph_sign(uint8_t       signature   [64],
                    const uint8_t private_key [32],
                    const uint8_t digest      [64]);

void ed25519ph_public_key(uint8_t       public_key  [32],
                          const uint8_t private_key [32]);

int ed25519ph_check(uint8_t       signature  [64],
                    const uint8_t public_key [32],
                    const uint8_t digest     [64]);
#endif
