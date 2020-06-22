#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>
#include <stdint.h>

size_t b64_encoded_size(size_t length);
size_t b64_decoded_size(const uint8_t input[], size_t input_size);
int b64_validate(const uint8_t input[], const size_t input_size);

void b64_encode(uint8_t output[],
                const uint8_t input[], size_t input_size);


void b64_decode(uint8_t output[],
                const uint8_t input[], const size_t input_size);
#endif
