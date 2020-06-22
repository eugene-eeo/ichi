#include <stddef.h>
#include <stdint.h>
#include "base64.h"


// Encoding table
const uint8_t b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Decoding table
int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
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

void b64_encode(uint8_t output[], const uint8_t input[], const size_t input_size)
{
    size_t i = 0;
    size_t j = 0;
    for (; i < input_size; i += 3, j += 4) {
        size_t v = input[i];
        v = i+1 < input_size ? v << 8 | input[i+1] : v << 8;
        v = i+2 < input_size ? v << 8 | input[i+2] : v << 8;

        output[j]   = b64chars[(v >> 18) & 0x3F];
        output[j+1] = b64chars[(v >> 12) & 0x3F];
        if (i+1 < input_size) {
            output[j+2] = b64chars[(v >> 6) & 0x3F];
        } else {
            output[j+2] = '=';
        }
        if (i+2 < input_size) {
            output[j+3] = b64chars[v & 0x3F];
        } else {
            output[j+3] = '=';
        }
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
    for (size_t i = 0; i < input_size; i++) {
        if (!b64_isvalidchar(input[i]))
            return -1;
    }
    return 0;
}

void b64_decode(uint8_t output[], const uint8_t input[], const size_t input_size) {
    size_t i = 0;
    size_t j = 0;
    size_t v;

    for (; i< input_size; i+=4, j+=3) {
        v = b64invs[input[i]-43];
        v = (v << 6) | b64invs[input[i+1]-43];
        v = input[i+2]=='=' ? v << 6 : (v << 6) | b64invs[input[i+2]-43];
        v = input[i+3]=='=' ? v << 6 : (v << 6) | b64invs[input[i+3]-43];

        output[j] = (v >> 16) & 0xFF;
        if (input[i+2] != '=')
            output[j+1] = (v >> 8) & 0xFF;
        if (input[i+3] != '=')
            output[j+2] = v & 0xFF;
    }
}
