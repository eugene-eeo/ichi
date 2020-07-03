#!/usr/bin/env bats

setup() {
    export PATH="$PWD:$PATH"
    run rm -rf test
    run mkdir test
}

@test "same output as base64" {
    run b64 -w76 < README.md
    [ "$status" = 0 ]
    [ "$output" = "$(base64 -w76 README.md)" ]

    run b64 -w0 < README.md
    [ "$status" = 0 ]
    [ "$output" = "$(base64 -w0 README.md)" ]
}

@test "decode + encode" {
    for file in README.md monocypher/monocypher.c; do
        b64 -w76 < "$file" > test/b64-enc
        run b64 -d < test/b64-enc
        [ "$status" = 0 ]
        [ "$output" = "$(cat $file)" ]
    done
}
