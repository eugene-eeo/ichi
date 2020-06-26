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
    size_t n;
    b64_encode_ctx ctx;
    b64_encode_init(&ctx);
    n = b64_encode_update(&ctx, output, input, input_size);
    b64_encode_final(&ctx, output + n);
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

static
int b64_isvalidchar(char c)
{
    if ((c >= '0' && c <= '9')
            || (c >= 'A' && c <= 'Z')
            || (c >= 'a' && c <= 'z')
            || (c == '+' || c == '/' || c == '='))
        return 1;
    return 0;
}

int b64_validate(const uint8_t input[], const size_t input_size) {
    // Validate that input is valid
    if (input_size % 4 != 0) {
        return -1;
    }
    return b64_decode_update_validate(input, input_size);
}

void b64_decode(uint8_t output[], const uint8_t input[], const size_t input_size) {
    size_t n;
    b64_decode_ctx ctx;
    b64_decode_init(&ctx);
    n = b64_decode_update(&ctx, output, input, input_size);
    b64_decode_final(&ctx, output + n);
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
    size_t c;
    // if we have any outstanding data from before
    if (ctx->bufsize > 0) {
        // load into ctx->buf first
        for (; (ctx->bufsize < 3) && (i < bufsize); i++, ctx->bufsize++)
            ctx->buf[ctx->bufsize] = buf[i];
        if (ctx->bufsize < 3)
            return j;
        // consume to produce 4 characters in out
        ctx->bufsize = 0;
        c = ctx->buf[0];
        c = c << 8 | ctx->buf[1];
        c = c << 8 | ctx->buf[2];
        out[j + 0] = b64chars[(c >> 18) & 0x3F];
        out[j + 1] = b64chars[(c >> 12) & 0x3F];
        out[j + 2] = b64chars[(c >> 6)  & 0x3F];
        out[j + 3] = b64chars[(c)       & 0x3F];
        j += 4;
    }
    for (; i < bufsize; i += 3) {
        // if we don't have enough, save in buf for later.
        if (i + 1 >= bufsize || i + 2 >= bufsize) {
            break;
        }
        c = buf[i];
        c = c << 8 | buf[i+1];
        c = c << 8 | buf[i+2];
        out[j + 0] = b64chars[(c >> 18) & 0x3F];
        out[j + 1] = b64chars[(c >> 12) & 0x3F];
        out[j + 2] = b64chars[(c >> 6)  & 0x3F];
        out[j + 3] = b64chars[(c)       & 0x3F];
        j += 4;
    }
    for (; i < bufsize; i++) {
        ctx->buf[ctx->bufsize] = buf[i];
        ctx->bufsize++;
    }
    return j;
}


size_t b64_encode_final(b64_encode_ctx *ctx,
                        uint8_t *out)
{
    size_t n = 0;
    // if we have any outstanding data from before
    if (ctx->bufsize > 0) {
        size_t c;
        c = ctx->buf[0];
        c = ctx->bufsize >= 2 ? c << 8 | ctx->buf[1] : c << 8;
        c = ctx->bufsize >= 3 ? c << 8 | ctx->buf[2] : c << 8;

        out[0] = b64chars[(c >> 18) & 0x3F];
        out[1] = b64chars[(c >> 12) & 0x3F];
        out[2] = ctx->bufsize >= 2 ? b64chars[(c >> 6) & 0x3F] : '=';
        out[3] = ctx->bufsize >= 3 ? b64chars[(c)      & 0x3F] : '=';
        n = 4;
    }
    // can reuse
    ctx->bufsize = 0;
    return n;
}

void b64_decode_init(b64_decode_ctx *ctx)
{
    ctx->bufsize = 0;
    ctx->eos = 0;
}

int b64_decode_eos(b64_decode_ctx* ctx)
{
    return ctx->eos;
}

int b64_decode_update_validate(const uint8_t *buf, size_t buf_size)
{
    for (size_t i = 0; i < buf_size; i++) {
        if (!b64_isvalidchar(buf[i])
                || (buf[i] == '='
                    && i != buf_size - 1
                    && i != buf_size - 2))
            return -1;
    }
    return 0;
}

size_t b64_decode_update_size(size_t input_size)
{
    size_t ret = input_size / 4 * 3;
    return ret + 3;
}

size_t b64_decode_update(b64_decode_ctx *ctx,
                               uint8_t *out,
                         const uint8_t *buf, size_t bufsize)
{
    if (ctx->eos)
        return 0;
    size_t i = 0; // where in buf
    size_t j = 0; // where in out
    size_t c;
    // if we have any outstanding data from before
    if (ctx->bufsize > 0) {
        // load into ctx->buf first
        for (; ctx->bufsize < 4 && i < bufsize; i++, ctx->bufsize++)
            ctx->buf[ctx->bufsize] = buf[i];
        if (ctx->bufsize < 4)
            return j;
        // consume
        ctx->bufsize = 0;
        c = b64invs[ctx->buf[0] - 43];
        c = (c << 6) | b64invs[ctx->buf[1] - 43];
        c = ctx->buf[2] == '=' ? (c << 6) : (c << 6) | b64invs[ctx->buf[2] - 43];
        c = ctx->buf[3] == '=' ? (c << 6) : (c << 6) | b64invs[ctx->buf[3] - 43];

        out[j] = (c >> 16) & 0xFF;
        if (ctx->buf[2] == '=') {
            ctx->eos = 1;
            return 1;
        } else {
            out[j+1] = (c >> 8) & 0xFF;
        }
        if (ctx->buf[3] == '=') {
            ctx->eos = 1;
            return 2;
        } else {
            out[j+2] = c & 0xFF;
        }
        j += 3;
    }
    for (; i < bufsize; i += 4) {
        if (i + 1 >= bufsize || i + 2 >= bufsize || i + 3 >= bufsize)
            break;
        c = b64invs[buf[i]-43];
        c = (c << 6) | b64invs[buf[i+1]-43];
        c = buf[i+2] == '=' ? c << 6 : (c << 6) | b64invs[buf[i+2]-43];
        c = buf[i+3] == '=' ? c << 6 : (c << 6) | b64invs[buf[i+3]-43];

        out[j] = (c >> 16) & 0xFF;
        if (buf[i+2] == '=') {
            ctx->eos = 1;
            return j + 1;
        } else {
            out[j+1] = (c >> 8) & 0xFF;
        }
        if (buf[i+3] == '=') {
            ctx->eos = 1;
            return j + 2;
        } else {
            out[j+2] = c & 0xFF;
        }
        j += 3;
    }
    // store remainder in ctx->buf
    for (; i < bufsize; i++) {
        ctx->buf[ctx->bufsize] = buf[i];
        ctx->bufsize++;
    }
    return j;
}

size_t b64_decode_final(b64_decode_ctx* ctx, uint8_t* out)
{
    size_t j = 0;
    size_t c;

    if (!ctx->eos && ctx->bufsize > 0) {
        c = b64invs[ctx->buf[0] - 43];
        c = (c << 6) | b64invs[ctx->buf[1] - 43];
        c = ctx->bufsize >= 3 ? (c << 6) : (c << 6) | b64invs[ctx->buf[2] - 43];
        c = ctx->bufsize >= 4 ? (c << 6) : (c << 6) | b64invs[ctx->buf[3] - 43];

        out[0] = (c >> 16) & 0xFF;
        if (ctx->bufsize >= 3) {
            if (ctx->buf[2] == '=') {
                ctx->eos = 1;
                j = 2;
                goto end;
            } else {
                out[1] = (c >> 8) & 0xFF;
            }
        }
        if (ctx->bufsize >= 4) {
            if (ctx->buf[3] == '=') {
                ctx->eos = 1;
                j = 3;
                goto end;
            } else {
                out[2] = c & 0xFF;
            }
        }
    }
end:
    ctx->bufsize = 0;
    ctx->eos = 0;
    return j;
}
