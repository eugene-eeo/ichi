
    █ █▀▀ █░█ █
    █ █▄▄ █▀█ █

simple set of tools for signing / encryption,
built on Monocypher.

Signing
-------

 - produce inline or detached signatures
 - keyring support

generate keys:

```sh
$ ichi-keygen -S -b id
```

sign + verify (inline):

```sh
$ echo "hello world!" \
    | ichi-sign -k id.sign.key
    | ichi-sign -V -p id.sign.pub
ichi-sign: good signature by 'id.sign.pub'
```

Encryption
----------

 - multiple recepients
 - trusted / untrusted encryption (whether you choose to
   use your private key or not)

generate keys:

```sh
$ ichi-keygen -L -b me
$ ichi-keygen -L -b id1
$ ichi-keygen -L -b id2
```

encrypt for `id1` and `id2`:

```sh
$ ichi-lock -E \
    -r id1.lock.pub \
    -r id2.lock.pub \
    -k me.lock.key  \
    -o encrypted \
    <(echo "Hello")
```

decrypt, and verify that `me` is the sender:

```sh
$ ichi-lock -D -k id1.key -v me.lock.pub encrypted
Hello
```
