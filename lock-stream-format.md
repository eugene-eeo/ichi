Lock Stream Format
==================

### Overview

`luck` uses an encryption format inspired by
Scuttlebutt's [box streams](https://ssbc.github.io/scuttlebutt-protocol-guide/#box-stream).
The Lock Stream format is split into 3 sections:

| key chunk    | block stream | digest chunk |
|:------------:|:------------:|:------------:|
| `KX \| PDKF` | `BLOCK*`     | `DIGEST`     |

 - **key chunk** -- determines the encryption key used; there are
   two modes (exactly one can be specified):
   1. `KX` -- public-key encryption, only recepient with corresponding
   secret key can unlock the stream.
   2. `PDKF` -- password encryption, recepient that knows password can
   unlock the stream.
 - **block stream** -- the content is encrypted and authenticated
   in fixed-size chunks of up to 4096 - this ensures that no individual
   block in the stream was tampered with.
 - **digest chunk** -- contains a hash of the (unencrypted) content
   used for verifying that no tampering of the block stream was done.


### Chunks

Each chunk has a leading byte known as the 'head'.
Reading the head then tells the decryption process how to
continue processing the stream.
In the format descriptions below, all integers are encoded
in unsigned LE format.


### `KX` chunk

| `@`  | _ephemeral pubkey_ |
|:----:|:------------------:|
|      | 32 bytes           |

During encryption, an ephemeral secret and public keypair is generated.
The encryption key is then calculated as:

    crypto_key_exchange(ephemeral_sk, recepient_pk)

The ephemeral public key is stored in the encryption. During decryption,
the recepient supplies their secret key and the encryption key is then:

    crypto_key_exchange(recepient_sk, ephemeral_pk)


### `PDKF` chunk

| `#`  | _memory cost_ | _time cost_ | _salt length_ | _salt_ |
|:----:|:-------------:|:-----------:|:-------------:|:------:|
|      | 4 bytes       | 1 byte      | 1 byte        |        |

The memory cost (in KiB) is encoded as 4-byte unsigned LE,
time cost (in iterations) as 1-byte, etc.
Current parameters in `luck`:

 - memory cost = 100 000 KiB (100 MB)
 - time cost = 3
 - salt length = 32
 - salt is randomly generated

During decryption, a password needs to be specified; the
decryption key is then calculated as:

    argon2i(password,
            parallelism=1,
            memory_cost=(memory cost) KiB,
            time_cost=(time cost) iterations,
            salt=salt)


### `BLOCK` chunk

| `b` | _mac1_   | _encrypted length_ | _mac2_   | _encrypted payload_ |
|:---:|:--------:|:------------------:|:--------:|:-------------------:|
|     | 16 bytes | 2 bytes            | 16 bytes |                     |


`BLOCK`s are produced by splitting up the original content into chunks
(_payload_) of up to 4096 bytes. _length_ denotes the length of the
_payload_ (in bytes).

During encryption and decryption, initially the nonce is 24-bytes of 0s.
It is incremented once to produce _mac1_, and again to produce _mac2_.
When encrypting/decrypting the next `BLOCK`, make sure to use the
incremented nonce -- in this sense the `nonce` serves as a message
counter. Values are produced as follows (in Monocypher):

    increment_nonce(nonce);
    crypto_lock(mac1,
                encrypted_length,
                shared_key,
                nonce,
                length, 2);
    increment_nonce(nonce);
    crypto_lock(mac2,
                encrypted_content,
                shared_key,
                nonce,
                content, content_length);

Similar to the aforementioend Box Stream, _mac1_ protects the _length_,
and _mac2_ protects the _payload_. Decryption is straightforward --
just provide the MACs and payloads to the `crypto_unlock` functions,
and increment the nonce appropriately.


### `DIGEST` chunk

| `$` | _digest_  |
|:---:|:---------:|
|     | 64 bytes  |

The _digest_ is computed as:

    blake2b(content, key=encryption key)

where `content` is the full, original content that was encrypted/decrypted.
This ensures that the overall `BLOCK` stream hasn't been tampered
with (i.e. no blocks are added/removed).
Upon decryption, _digest_ needs to be compared with one computed
by the decryptor.
