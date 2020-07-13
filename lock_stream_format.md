# Lock Stream format

Aims to provide a simple and secure encryption format for
(potentially large) streams. Overview:

    ┌────────────┬───────────────────────────────┬───────────────────────────┬────────────┐
    │ nonce (24) | '@' + pubkey (32) + nrecp (1) | mac + enc(K) (48 * nrecp) | ENC STREAM |
    └────────────┼───────────────────────────────┴───────────────────────────┼────────────┘
                 | '#' + mcost (4) + tcost (1) + salt_length (1) + salt      |
                 └───────────────────────────────────────────────────────────┘

The nonce is randomly generated 24 bytes.

There are 2 key modes:

 1. KX mode (`@`) -- allows for sender verification and multiple recepients.
 2. PDKF mode (`#`) -- password encryption.


### `KX` Mode

The encryption key `K` is randomly generated 32 bytes.
`pubkey` is the public key of the sender, or the public key of a
randomly generated keypair.
`nrecp` is the number of recepients (1-255) (1 byte LE unsigned).
`mac + enc(K)` sequence is produced as follows (using Monocypher):
for each recepient,

 - compute the shared key between the sender's private key
   and the recepient public key using `crypto_key_exchange`.
 - using `crypto_lock`, encrypt `K` with the nonce being 24 zeros,
   and the encryption key beiing the shared key.
 - write this 16 + 32 = 48 bytes to the output stream.

To derive the key in `KX` mode we need to try `nrecp` many 48-byte chunks,
one after another until we find one that unlocks.


### `PDKF` Mode

The algorithm used is Argon2i (with a parallelism of 1).
`mcost` is the memory cost (in KiB), 4-byte LE unsigned.
`tcost` is the time cost (iterations), 1-byte LE unsigned.
`salt_length` is the salt length (in bytes), 1-byte LE unsigned.

To compute the encryption key, use Argon2i with the parameters
and the user-supplied password.

There are some bounds on the parameters:

 - 8 <= `mcost` <= 100000
 - 1 <= `tcost` <= 10
 - 8 <= `salt_length` <= 255


### Encryption Stream

The plaintext is divided into chunks of 32KiB.
Each chunk is encrypted as follows:

    ┌───────────┬─────────────────┬───────────┬────────────────────────────────────┐
    │ mac1 (16) │ enc(length) (2) │ mac2 (16) │ enc('B' + chunk) (1...(32KiB + 1)) │
    └───────────┴─────────────────┴───────────┴────────────────────────────────────┘

`length` is the length of the chunk + 1, 2-byte LE unsigned.
`mac1` and `enc(length)` is computed by incrementing the nonce
once and using `crypto_lock`.
`mac2` and `enc(chunk)` are prodcued by incrementing the nonce
again and using `crypto_lock`.

At the end of the stream, we furthermore add the digest chunk:

    ┌───────────┬─────────────────┬───────────┬────────────────────────┐
    │ mac1 (16) │ enc(length) (2) │ mac2 (16) │ enc('$' + digest) (65) │
    └───────────┴─────────────────┴───────────┴────────────────────────┘

where `length` = 65, `mac1` and `mac2` are produced as before,
and `digest` is the 64-byte blake2b digest of the entire plaintext.

To decrypt the encryption stream:

 1. read 18 bytes, increment the nonce and `crypto_unlock`
 2. read `$length` bytes, increment the nonce and `crypto_unlock`
 3. look at the first byte:
    - if it's `B` then it's a plaintext chunk
    - if it's `$` then it's a digest chunk

