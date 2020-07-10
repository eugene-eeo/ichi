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
    luck -g test/id

    luck -ek test/id.pk README.md > test/enc-pubkey
    luck -ep password   README.md > test/enc-pdkf

    run luck -dp password test/enc-pubkey
    [ "$status" != 0 ]

    run luck -dp password test/enc-pdkf
    [ "$status" = 0 ]
    [ "$output" = "$(cat README.md)" ]
}

@test 'askpass' {
    run luck -ea 'false' README.md
    [ "$status" != 0 ]

    luck -ea 'echo 1' README.md > test/enc
    run luck -da 'echo 1' test/enc
    [ "$status" = 0 ]
    [ "$output" = "$(cat README.md)" ]
}
