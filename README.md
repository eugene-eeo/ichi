
    █ █▀▀ █░█ █
    █ █▄▄ █▀█ █

simple set of tools for signing / encryption,
built on Monocypher.

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
    -R id1.pub \
    -R id2.pub \
    -k me.key  \
    -o encrypted \
    <(echo "Hello")
```

decrypt, and verify that `me` is the sender:

```sh
$ luck -D -k id1.key -V me.pub encrypted
Hello
```
