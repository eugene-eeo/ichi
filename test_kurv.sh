#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    run rm -rf test
    run mkdir test
    run mkdir test/keyring
}

@test "help page" {
    # really just a regression so I don't fuck up kurv -h
    # by forgetting to break again.
    run kurv -h
    [ "$status" -eq 0 ]
}

@test "key generation" {
    run kurv -G test/id
    [ "$status" -eq 0 ]
    [ -f 'test/id.pub' ]
    [ -f 'test/id.priv' ]
}

@test "file signing and checking" {
    kurv -G test/id
    kurv -G test/id2

    kurv -Sk test/id.priv README.md > test/signed.txt
    [ -f 'test/signed.txt' ]

    # shellcheck disable=SC2002
    cat README.md | kurv -Sk test/id.priv > test/signed.txt
    [ -f 'test/signed.txt' ]

    # file w/o signature should fail
    run kurv -Ck test/id.pub README.md
    [ "$status" -ne 0 ]

    # file with signature
    run kurv -Ck test/id.pub test/signed.txt
    [ "$status" -eq 0 ]

    # should fail
    run kurv -Ck test/id2.pub test/signed.txt
    [ "$status" -ne 0 ]
}

@test "file double signing" {
    # check that we can sign a file twice, should validate correctly.
    kurv -G test/id
    kurv -G test/id2

    kurv -Sk test/id.priv README.md > test/f1
    kurv -Sk test/id2.priv test/f1 > test/f2

    # shellcheck disable=SC2002
    cat test/f2 | kurv -Ck test/id2.pub
    # shellcheck disable=SC2002
    cat test/f1 | kurv -Ck test/id.pub
}

@test "checking options" {
    # check -i and -o options are respected
    kurv -G test/id
    kurv -Sk test/id.priv README.md > test/output.txt

    # with -i specified
    kurv -Ck test/id.pub -i test/output.txt 2> test/id.txt
    [ "$(cat test/id.txt)" = 'kurv: pubkey: test/id.pub' ]

    # with -o specified
    output=$(kurv -Ck test/id.pub -o test/output.txt)
    [ "$output" = "$(cat README.md)" ]

    # with -io specified
    output=$(kurv -Ck test/id.pub -io test/output.txt 2> test/id.txt)
    [ "$output" = "$(cat README.md)" ]
    [ "$(cat test/id.txt)" = 'kurv: pubkey: test/id.pub' ]
}

@test "keyring support" {
    kurv -G test/keyring/a
    kurv -G test/keyring/b
    kurv -G test/keyring/c
    kurv -G test/id

    kurv -Sk test/id.priv README.md > test/u.txt
    KURV_KEYRING="test/keyring/" run kurv -c u.txt
    [ "$status" -ne 0 ]

    for id in test/keyring/{a,b,c}; do
        kurv -Sk "$id.priv" README.md > test/output.txt

        # without KURV_KEYRING
        run kurv -C test/output.txt
        [ "$status" -ne 0 ]

        # with and w/o trailing slash
        for keyring_dir in "test/keyring/" "test/keyring"; do
            KURV_KEYRING="$keyring_dir" kurv -Ci test/output.txt 2>test/id.txt
            [ "$(cat test/id.txt)" = "kurv: pubkey: $id.pub" ]
        done
    done
}

@test "detach" {
    kurv -G test/id
    output=$(kurv -Sk test/id.priv monocypher/monocypher.c | kurv -D)
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}

@test "regression: empty stream" {
    kurv -G test/id
    touch test/empty
    ! kurv -Ck test/id.pub test/empty 2> test/err
    [[ "$(cat test/err)" == *"invalid stream"* ]]

    ! kurv -D test/empty 2> test/err
    [[ "$(cat test/err)" == *"invalid stream"* ]]
}
