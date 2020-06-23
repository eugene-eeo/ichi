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
    run kurv -g test/id
    [ "$status" -eq 0 ]
    [ -f 'test/id.pub' ]
    [ -f 'test/id.priv' ]
}

@test "file signing and checking" {
    kurv -g test/id
    kurv -g test/id2

    kurv -s README -P test/id.priv > test/signed.txt
    [ -f 'test/signed.txt' ]

    # file w/o signature should fail
    run kurv -c README -p test/id.pub
    [ "$status" -ne 0 ]

    # file with signature
    run kurv -c test/signed.txt -p test/id.pub
    [ "$status" -eq 0 ]

    # should fail
    run kurv -c test/signed.txt -p test/id2.pub
    [ "$status" -ne 0 ]
}

@test "file double signing" {
    # check that we can sign a file twice, should validate correctly.
    kurv -g test/id
    kurv -g test/id2

    kurv -s README -P test/id.priv \
        | kurv -s - -P test/id2.priv \
        | kurv -c - -p test/id2.pub -o \
        | kurv -c - -p test/id.pub -o
}

@test "checking options" {
    # check -i and -o options are respected
    kurv -g test/id
    kurv -s README -P test/id.priv > test/output.txt

    # with -i specified
    run kurv -c test/output.txt -p test/id.pub -i
    [ "$status" -eq 0 ]
    [ "$output" = 'test/id.pub' ]

    # with -o specified
    run kurv -c test/output.txt -p test/id.pub -o
    [ "$status" -eq 0 ]
    [ "$output" = "$(cat README)" ]

    # with -i and -o specified
    run kurv -c test/output.txt -p test/id.pub -i -o
    [ "$status" -eq 0 ]
    [ "$output" = "test/id.pub
$(cat README)" ]
}

@test "keyring support" {
    kurv -g test/keyring/a
    kurv -g test/keyring/b
    kurv -g test/keyring/c

    for id in test/keyring/{a,b,c}; do
        kurv -s README -P "$id.priv" > test/output.txt

        # without KURV_KEYRING
        run kurv -c test/output.txt
        [ "$status" -ne 0 ]

        bname=$(basename "$id")

        KURV_KEYRING="test/keyring/" run kurv -c test/output.txt -i
        [ "$status" -eq 0 ]
        [ "$output" = "$bname.pub" ]

        # KURV_KEYRING without ending slash
        KURV_KEYRING="test/keyring" run kurv -c test/output.txt -i
        [ "$status" -eq 0 ]
        [ "$output" = "$bname.pub" ]
    done
}

@test "detach" {
    kurv -g test/id
    output=$(kurv -s monocypher/monocypher.c -P test/id.priv | kurv -d -)
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}
