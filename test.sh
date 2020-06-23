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

    kurv -sP test/id.priv README > test/signed.txt
    [ -f 'test/signed.txt' ]

    # file w/o signature should fail
    run kurv -cp test/id.pub README
    [ "$status" -ne 0 ]

    # file with signature
    run kurv -cp test/id.pub test/signed.txt
    [ "$status" -eq 0 ]

    # should fail
    run kurv -cp test/id2.pub test/signed.txt
    [ "$status" -ne 0 ]
}

@test "file double signing" {
    # check that we can sign a file twice, should validate correctly.
    kurv -g test/id
    kurv -g test/id2

    kurv -sP test/id.priv README \
        | kurv -sP test/id2.priv \
        | kurv -cp test/id2.pub -o \
        | kurv -cp test/id.pub -o
}

@test "checking options" {
    # check -i and -o options are respected
    kurv -g test/id
    kurv -sP test/id.priv README > test/output.txt

    # with -i specified
    run kurv -cp test/id.pub -i test/output.txt
    [ "$status" -eq 0 ]
    [ "$output" = 'test/id.pub' ]

    # with -o specified
    run kurv -cp test/id.pub -o test/output.txt
    [ "$status" -eq 0 ]
    [ "$output" = "$(cat README)" ]

    # with -i and -o specified
    run kurv -cp test/id.pub -io test/output.txt
    [ "$status" -eq 0 ]
    [ "$output" = "test/id.pub
$(cat README)" ]
}

@test "keyring support" {
    kurv -g test/keyring/a
    kurv -g test/keyring/b
    kurv -g test/keyring/c

    for id in test/keyring/{a,b,c}; do
        kurv -sP "$id.priv" README > test/output.txt

        # without KURV_KEYRING
        run kurv -c test/output.txt
        [ "$status" -ne 0 ]

        KURV_KEYRING="test/keyring/" run kurv -ci test/output.txt
        [ "$status" -eq 0 ]
        [ "$output" = "$id.pub" ]

        # KURV_KEYRING without ending slash
        KURV_KEYRING="test/keyring" run kurv -ci test/output.txt
        [ "$status" -eq 0 ]
        [ "$output" = "$id.pub" ]
    done
}

@test "detach" {
    kurv -g test/id
    output=$(kurv -sP test/id.priv monocypher/monocypher.c | kurv -d)
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}
