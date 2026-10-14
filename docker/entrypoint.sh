#!/bin/bash

function shutdown {
    echo "sending TPM stop signal to pid $pid"
    echo -ne '\x00\x00\x00\x15' | nc localhost 2321
    wait $pid
    return 0
}

trap "shutdown" INT TERM

/run/bin/tpm_server &
pid=$!

wait $pid
