#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
        test/framework-test
        test/delay-test
        test/shutdown-test
        test/lpm
        test/lpm-embedded
        test/nat
        test/tcp-check
        test/sctp-test
        test/config-test
        test/reset-parse
        test/packet_generation
        test/embedded-scheduler-test
        test/embedded-scheduler-dependency-test
        test/tcp_payload
        test/macswap
        # ZCSI examples
        test/acl-fw
        test/tcp-reconstruction
        test/maglev
        test/chain-test
        test/packet_test
        # PVN examples
        test/tls-validator-filter
        test/tls-validator-groupby
        test/wd-rdr-proxy
        test/rdr-nat-filter
        test/rdr-nat-groupby
        test/transcoder-nat-filter
        test/transcoder-nat-groupby
        test/rdr-proxy
        test/p2p
        test/p2p-nat-filter
        test/p2p-nat-groupby
        test/pktgen-test
        test/adv-acl
        test/lpm-test
)

