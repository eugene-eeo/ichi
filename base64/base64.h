#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>
#include <stdint.h>

size_t b64_encoded_size(size_t length);
size_t b64_decoded_size(const uint8_t input[], size_t input_size);
int b64_validate(const uint8_t input[], const size_t input_size);

// Direct interface
void b64_encode(uint8_t output[],
                const uint8_t input[], size_t input_size);


void b64_decode(uint8_t output[],
                const uint8_t input[], const size_t input_size);

// Incremental interface
typedef struct {
    uint8_t buf[3];
    size_t  bufsize;
} b64_encode_ctx;

void   b64_encode_init(b64_encode_ctx *ctx);
size_t b64_encode_update_size(size_t bufsize);
size_t b64_encode_update(b64_encode_ctx *ctx,
                         uint8_t out[],
                         const uint8_t buf[], size_t bufsize);
size_t b64_encode_final(b64_encode_ctx *ctx,
                        uint8_t out[]);

typedef struct {
    uint8_t buf[4];
    size_t  bufsize;
    uint8_t eos;
    uint8_t err;
} b64_decode_ctx;

void   b64_decode_init(b64_decode_ctx *ctx);
size_t b64_decode_update_size(size_t bufsize);
size_t b64_decode_update(b64_decode_ctx *ctx,
                         uint8_t *out,
                         const uint8_t *buf, size_t bufsize);
void   b64_decode_final(b64_decode_ctx *ctx);
int    b64_decode_err(b64_decode_ctx *ctx);
#endif
