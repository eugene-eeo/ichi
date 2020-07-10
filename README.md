
    █ █▀▀ █░█ █
    █ █▄▄ █▀█ █

simple set of tools for signing / encryption,
built on Monocypher.

Signing
-------

```sh
# generate keypair
$ kurv -g id
$ cat id.{pub,priv}
P/Vkey2lTatqY5dHpxgxPrdSnbv4cQih+Gn7Flgs1tQ=
...

# signing
$ kurv -sk id.priv README
...
----BEGIN KURV SIGNATURE----
bQ3Mx3Vb0tdmb1GF2f0jgLm8GJpvQhYFYe2kkrOHkno5
yOhnAi2Dl9Gmpt/Tx9aG4VyWTUjfdVyx7QI1xrpgCQ==
----END KURV SIGNATURE----

# checking signatures
$ (cat signed-file | kurv -ck id.pub) && echo "ok"
ok
```

Encryption
----------

```sh
$ luck -g id
$ echo "Hello" \
   | luck -ek id.pk \  # encrypt for recepient
   | luck -dk id.sk    # decrypt
Hello
$ export LUCK_ASKPASS='zenity --password'
$ echo "World" \
   | luck -ep \ # with password
   | luck -dp
World
```
