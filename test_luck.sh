#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    run mkdir -p test
    run rm -rf test/*
}

@test 'id generation' {
    run luck -G test/id
    [ "$status" = 0 ]
    [ -f 'test/id.sk' ]
    [ -f 'test/id.pk' ]
}

@test 'encrypt + decrypt' {
    luck -G test/id
    luck -Ek test/id.pk monocypher/monocypher.c > test/enc
    luck -Dk test/id.sk test/enc > test/dec
    [ "$(cat test/dec)" = "$(cat monocypher/monocypher.c)" ]

    # decrypt with stream cutoff
    run luck -Dk test/id.sk <(head -c 200 test/enc)
    [ "$status" != 0 ]

    # decrypt with invalid id
    luck -G test/eve
    run luck -Dk test/eve.sk test/enc
    [ "$status" != 0 ]
}

@test 'nested encryption' {
    luck -G test/id1
    luck -G test/id2
    luck -Ek test/id1.pk monocypher/monocypher.c \
        | luck -Ek test/id2.pk \
        > test/enc
    luck -Dk test/id2.sk test/enc > test/dec
    run luck -Dk test/id1.sk test/dec
    [ "$status" = 0 ]
    [ "$output" = "$(cat monocypher/monocypher.c)" ]
}

@test 'password encryption (password)' {
    luck -Ep 123 README.md > test/enc
    luck -Dp 123 test/enc > test/dec
    [ "$(cat test/dec)" = "$(cat README.md)" ]

    run luck -Dp 12 test/enc
    [ "$status" != 0 ]
}

@test 'password encryption (askpass)' {
    # bad askpass output
    LUCK_ASKPASS='false' run luck -Ea README.md
    [ "$status" != 0 ]

    LUCK_ASKPASS='echo abcdef' luck -Ea README.md > test/enc
    LUCK_ASKPASS='echo abcdef' luck -Da test/enc > test/dec
    [ "$(cat test/dec)" = "$(cat README.md)" ]

    run LUCK_ASKPASS='echo abc' luck -Da test/enc
    [ "$status" != 0 ]
}
