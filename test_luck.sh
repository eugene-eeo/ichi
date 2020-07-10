#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    run mkdir -p test
    run rm -rf test/*
}

@test 'id generation' {
    run luck -g test/id
    [ "$status" = 0 ]
    [ -f 'test/id.sk' ]
    [ -f 'test/id.pk' ]
}

@test 'print public key' {
    luck -g test/id
    run luck -wk test/id.sk
    [ "$status" = 0 ]
    [ "$output" = "$(cat test/id.pk)" ]
}

@test 'encrypt + decrypt' {
    luck -g test/id
    luck -ek test/id.pk monocypher/monocypher.c > test/enc
    run luck -dk test/id.sk test/enc
    [ "$status" = 0 ]
    [ "$output" = "$(cat monocypher/monocypher.c)" ]

    # decrypt with stream cutoff
    run luck -dk test/id.sk <(head -c 200 test/enc)
    [ "$status" != 0 ]

    # decrypt with invalid id
    luck -g test/eve
    run luck -dk test/eve.sk test/enc
    [ "$status" != 0 ]
}

@test 'nested encryption' {
    luck -g test/id1
    luck -g test/id2
    luck -ek test/id1.pk monocypher/monocypher.c \
        | luck -ek test/id2.pk \
        > test/enc
    luck -dk test/id2.sk test/enc > test/dec
    run luck -dk test/id1.sk test/dec
    [ "$status" = 0 ]
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}

@test 'password encryption' {
    # no askpass
    run luck -ep README.md
    [ "$status" != 0 ]

    # bad askpass output
    LUCK_ASKPASS='false' run luck -ep README.md
    [ "$status" != 0 ]

    LUCK_ASKPASS='echo abcdef' luck -ep README.md > test/enc
    LUCK_ASKPASS='echo abcdef' luck -dp test/enc > test/dec
    [ "$(cat test/dec)" = "$(cat README.md)" ]
}
