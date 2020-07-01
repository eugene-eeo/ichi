#include <stddef.h>
#include <stdint.h>
#include "base64.h"

// Encoding table
static const uint8_t b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Decoding table
static const int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51 };


size_t b64_encoded_size(size_t length) {
    size_t ret = length;
    if (length % 3 != 0) {
        ret += 3 - (length % 3);
    }
    ret /= 3;
    ret *= 4;
    return ret;
}

// Direct interface
void b64_encode(uint8_t output[], const uint8_t input[], const size_t input_size)
{
    size_t v;
    size_t i, j;
    for (i = 0, j = 0; i < input_size; i+=3, j+=4) {
        v = input[i];
        v = i + 1 < input_size ? v << 8 | input[i+1] : v << 8;
        v = i + 2 < input_size ? v << 8 | input[i+2] : v << 8;
        output[j]   = b64chars[(v >> 18) & 0x3F];
        output[j+1] = b64chars[(v >> 12) & 0x3F];
        output[j+2] = (i+1 < input_size) ? b64chars[(v >> 6) & 0x3F] : '=';
        output[j+3] = (i+2 < input_size) ? b64chars[(v)      & 0x3F] : '=';
    }
}

size_t b64_decoded_size(const uint8_t input[], size_t input_size)
{
    if (input == NULL)
        return 0;
    size_t ret = input_size / 4 * 3;
    for (size_t i = input_size; i-->0; ) {
        if (input[i] == '=') {
            ret--;
        } else {
            break;
        }
    }
    return ret;
}

static inline
int b64_isvalidchar(char c)
{
    if ((c >= '0' && c <= '9')
            || (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z')
            || c == '+' || c == '/' || c == '=')
        return 1;
    return 0;
}

int b64_validate(const uint8_t input[], const size_t input_size) {
    // Validate that input is valid
    if (input_size % 4 != 0)
        return -1;
    for (size_t i = 0; i < input_size; i++) {
        if (!b64_isvalidchar(input[i]))
            return -1;
        if (input[i] == '=') {
            if (i == input_size - 1) return 0;
            if (i == input_size - 2 && input[i+1] == '=') return 0;
            return -1;
        }
    }
    return 0;
}

void b64_decode(uint8_t output[], const uint8_t input[], const size_t input_size) {
    size_t v;
    size_t i, j;
    for (i=0, j=0; i < input_size; i+=4, j+=3) {
        v = b64invs[input[i]-43];
        v = (v << 6) | b64invs[input[i+1]-43];
        v = input[i+2] == '=' ? v << 6 : (v << 6) | b64invs[input[i+2]-43];
        v = input[i+3] == '=' ? v << 6 : (v << 6) | b64invs[input[i+3]-43];

        output[j] = (v >> 16) & 0xFF;
        if (input[i+2] != '=')
            output[j+1] = (v >> 8) & 0xFF;
        if (input[i+3] != '=')
            output[j+2] = v & 0xFF;
    }
}

void b64_encode_init(b64_encode_ctx *ctx)
{
    ctx->bufsize = 0;
}

size_t b64_encode_update_size(size_t bufsize)
{
    return b64_encoded_size(bufsize) + 4;
}

size_t b64_encode_update(b64_encode_ctx *ctx,
                               uint8_t *out,
                         const uint8_t *buf, size_t bufsize)
{
    size_t i = 0; // where in buf
    size_t j = 0; // where in out
    if (ctx->bufsize > 0) {
        for (; (ctx->bufsize < 3) && (i < bufsize); i++, ctx->bufsize++)
            ctx->buf[ctx->bufsize] = buf[i];
        if (ctx->bufsize < 3)
            return j;
        // consume
        b64_encode(out + j, ctx->buf, 3);
        ctx->bufsize = 0;
        j += 4;
    }
    for (; i + 3 < bufsize; i += 3, j += 4)
        b64_encode(out + j, buf + i, 3);
    for (; i < bufsize; i++, ctx->bufsize++)
        ctx->buf[ctx->bufsize] = buf[i];
    return j;
}

size_t b64_encode_final(b64_encode_ctx *ctx,
                        uint8_t *out)
{
    size_t n = ctx->bufsize > 0 ? 4 : 0;
    b64_encode(out, ctx->buf, ctx->bufsize);
    ctx->bufsize = 0;
    return n;
}

void b64_decode_init(b64_decode_ctx *ctx)
{
    ctx->bufsize = 0;
    ctx->eos = 0;
    ctx->err = 0;
}

size_t b64_decode_update_size(size_t input_size)
{
    // conservative estimate...
    size_t ret = input_size / 4 * 3;
    return ret + 3;
}

size_t b64_decode_update(b64_decode_ctx *ctx,
                         uint8_t *out,
                         const uint8_t *buf, size_t bufsize)
{
    size_t i = 0, // where in buf
           j = 0; // where in out
    while (i < bufsize && !ctx->eos && !ctx->err) {
        for (; (ctx->bufsize < 4) && (i < bufsize); i++, ctx->bufsize++)
            ctx->buf[ctx->bufsize] = buf[i];
        if (ctx->bufsize < 4)
            break;
        // consume buf
        ctx->bufsize = 0;
        ctx->err = b64_validate(ctx->buf, 4) != 0;
        if (ctx->err)
            break;
        b64_decode(out + j, ctx->buf, 4);
        j += 3;
        if (ctx->buf[2] == '=') { ctx->eos = 1; j--; }
        if (ctx->buf[3] == '=') { ctx->eos = 1; j--; }
    }
    if (ctx->eos && i != bufsize)
        ctx->err = 1;
    return j;
}

void b64_decode_final(b64_decode_ctx *ctx)
{
    ctx->err = ctx->bufsize != 0;
    ctx->eos = 1;
    ctx->bufsize = 0;
}

int b64_decode_err(b64_decode_ctx *ctx) { return (int)ctx->err; }
