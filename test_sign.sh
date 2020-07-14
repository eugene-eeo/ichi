#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    rm -rf test
    mkdir -p test
}

@test 'keygen' {
    ichi-keygen -S -b test/id
    [ -f test/id.sign.key ]
    [ -f test/id.sign.pub ]
}

@test 'sign + unsign (inline)' {
    ichi-keygen -S -b test/a
    ichi-keygen -S -b test/b

    ichi-sign -k test/a.sign.key -o test/signed README.md
    ichi-sign -V -p test/a.sign.pub test/signed

    run ichi-sign -V -p test/b.sign.pub test/signed
    [ "$status" != 0 ]
}

@test 'trim' {
    ichi-keygen -S -b test/a
    ichi-sign -k test/a.sign.key -o test/signed README.md
    ichi-sign -T test/signed -o test/detached
    [ "$(cat test/detached)" = "$(cat README.md)" ]
}

@test 'sign + unsign (detached)' {
    ichi-keygen -S -b test/a
    ichi-keygen -S -b test/b

    ichi-sign -k test/a.sign.key -d -o test/sig README.md
    ichi-sign -V -p test/a.sign.pub -s test/sig README.md

    run ichi-sign -V -p test/b.pub -s test/sig README.md
    [ "$status" != 0 ]
}

@test 'keyring' {
    ichi-keygen -S -b test/a
    ichi-keygen -S -b test/b
    ichi-keygen -S -b test/c

    ichi-sign -k test/a.sign.key -d -o test/sig README.md
    ichi-sign -k test/a.sign.key -o test/signed README.md

    for dirname in test test/; do
        ICHI_SIGN_KEYRING="$dirname" ichi-sign -V -s test/sig README.md
        ICHI_SIGN_KEYRING="$dirname" ichi-sign -V test/signed
    done

    # unset = fail
    run ichi-sign -V -s test/sig README.md
    [ "$status" != 0 ]
    run ichi-sign -V test/signed
    [ "$status" != 0 ]
}
