#include <stdio.h>
#include "monocypher/monocypher.h"
#include "sign_ph.h"

int main()
{
    uint8_t msg[7] = "message";
    uint8_t sk [32] = { 0x1, 0x2, 0x3, 0x4 },
            pk [32];
    uint8_t digest    [64],
            signature [64];

    crypto_blake2b(digest, msg, sizeof(msg));

    sign_ph_public_key(pk, sk);
    sign_ph_sign(signature, sk, digest);
    int rv = sign_ph_check(signature, pk, digest);
    printf("%d\n", rv);
}
