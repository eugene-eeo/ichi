#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    rm -rf test
    mkdir -p test
}

@test 'keygen' {
    ichi-keygen -L -b test/id
    [ -f test/id.key ]
    [ -f test/id.pub ]
}

@test 'encrypt (pubkey)' {
    ichi-keygen -L -b test/x
    ichi-keygen -L -b test/a
    ichi-keygen -L -b test/b
    ichi-keygen -L -b test/c

    ichi-lock -E -r test/a.pub \
                 -r test/b.pub \
                 -r test/c.pub \
                 -k test/x.key \
                 -o test/enc \
                 README.md
    [ -f test/enc ]

    # each recepient should be able to decrypt
    for key in a b c; do
        ichi-lock -D -v test/x.pub \
                     -k "test/${key}.key" \
                     -o test/out \
                     test/enc
        [ "$(cat test/out)" = "$(cat README.md)" ]
    done

    # incorrect sender verification
    run ichi-lock -D -v test/a.pub -k test/a.key test/enc
    [ "$status" != 0 ]

    # epehemeral keypair
    ichi-lock -E -r test/x.pub \
                 -o test/enc \
                 README.md
    ichi-lock -D -k test/x.key -o test/dec test/enc
    [ "$(cat test/dec)" = "$(cat README.md)" ]
}

@test 'password encryption' {
    ichi-lock -E -p <(echo 123) -o test/enc README.md
    ichi-lock -D -p <(echo 123) -o test/dec test/enc
    [ "$(cat test/dec)" = "$(cat README.md)" ]

    run ichi-lock -D -p <(echo abc) -o test/dec test/enc
    [ "$status" != 0 ]
}
