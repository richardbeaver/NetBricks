#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
        test/framework-test
        test/delay-test
        test/shutdown-test
        test/chain-test
        test/lpm
        test/lpm-embedded
        test/nat
        test/maglev
        test/tcp-check
        test/sctp-test
        test/config-test
        test/reset-parse
        test/tcp-reconstruction
        test/acl-fw
        test/packet_generation
        test/packet-test
        test/embedded-scheduler-test
        test/embedded-scheduler-dependency-test
        test/tcp_payload
        test/macswap
)

