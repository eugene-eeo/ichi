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
    luck -ek test/id.pk README > test/README-enc
    run luck -dk test/id.sk test/README-enc
    [ "$status" = 0 ]
    [ "$output" = "$(cat README)" ]

    # decrypt with stream cutoff
    run luck -dk test/id.sk <(head -c 200 test/README-enc)
    [ "$status" != 0 ]

    # decrypt with invalid id
    luck -g test/eve
    run luck -dk test/eve.sk test/README-enc
    [ "$status" != 0 ]
}
