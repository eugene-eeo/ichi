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

    kurv -sk test/id.priv README.md > test/signed.txt
    [ -f 'test/signed.txt' ]

    # shellcheck disable=SC2002
    cat README.md | kurv -sk test/id.priv > test/signed.txt
    [ -f 'test/signed.txt' ]

    # file w/o signature should fail
    run kurv -ck test/id.pub README.md
    [ "$status" -ne 0 ]

    # file with signature
    run kurv -ck test/id.pub test/signed.txt
    [ "$status" -eq 0 ]

    # should fail
    run kurv -ck test/id2.pub test/signed.txt
    [ "$status" -ne 0 ]
}

@test "file double signing" {
    # check that we can sign a file twice, should validate correctly.
    kurv -g test/id
    kurv -g test/id2

    kurv -sk test/id.priv README.md > test/f1
    kurv -sk test/id2.priv test/f1 > test/f2

    # shellcheck disable=SC2002
    cat test/f2 | kurv -ck test/id2.pub
    # shellcheck disable=SC2002
    cat test/f1 | kurv -ck test/id.pub
}

@test "checking options" {
    # check -i and -o options are respected
    kurv -g test/id
    kurv -sk test/id.priv README.md > test/output.txt

    # with -i specified
    run kurv -ck test/id.pub -i test/output.txt
    [ "$status" -eq 0 ]
    [ "$output" = 'test/id.pub' ]
}

@test "keyring support" {
    kurv -g test/keyring/a
    kurv -g test/keyring/b
    kurv -g test/keyring/c
    kurv -g test/id

    kurv -sk test/id.priv README.md > test/u.txt
    KURV_KEYRING="test/keyring/" run kurv -c u.txt
    [ "$status" -ne 0 ]

    for id in test/keyring/{a,b,c}; do
        kurv -sk "$id.priv" README.md > test/output.txt

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
    output=$(kurv -sk test/id.priv monocypher/monocypher.c | kurv -d)
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}

@test "print public key" {
    kurv -g test/id
    run kurv -wk test/id.priv
    [ "$status" = 0 ]
    [ "$output" = "$(cat test/id.pub)" ]
}

@test "regression: empty stream" {
    kurv -g test/id
    touch test/empty
    ! kurv -ck test/id.pub test/empty 2> test/err
    [[ "$(cat test/err)" == *"invalid stream"* ]]

    ! kurv -d test/empty 2> test/err
    [[ "$(cat test/err)" == *"invalid stream"* ]]
}
