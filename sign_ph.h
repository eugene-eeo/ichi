#ifndef SIGN_PH_H
#define SIGN_PH_H

#include <stdint.h>
#include <stddef.h>

void sign_ph_sign(uint8_t       signature   [64],
                  const uint8_t private_key [32],
                  const uint8_t digest      [64]);

void sign_ph_public_key(uint8_t       public_key  [32],
                        const uint8_t private_key [32]);

int sign_ph_check(uint8_t       signature  [64],
                  const uint8_t public_key [32],
                  const uint8_t digest     [64]);
#endif
