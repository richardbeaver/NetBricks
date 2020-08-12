#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
	# test/framework-test
	# test/delay-test
	# test/shutdown-test
	# test/lpm
	# test/lpm-embedded
	# test/nat
	# test/tcp-check
	# test/sctp-test
	# test/config-test
	# test/reset-parse
	# test/packet_generation
	# test/embedded-scheduler-test
	# test/embedded-scheduler-dependency-test
	# test/tcp_payload
	# test/macswap
	# ZCSI examples
	# test/acl-fw
	# test/tcp-reconstruction
	# test/maglev
	# test/chain-test
	# test/lpm-test
	# test/packet_test
	# PVN examples (in application format)
	test/app-tlsv_g
	test/app-tlsv_t
	test/app-rdr_g
	test/app-rdr_t
	test/app-p2p_g
	test/app-p2p_t
	test/app-xcdr_g
	test/app-xcdr_t
	# PVN examples (for latency measurement)
	# test/tls-validator-groupby
	# test/tls-validator-transform
	# test/rdr-groupby
	# test/rdr-transform
	# test/p2p-groupby
	# test/p2p-transform
	# test/transcoder-groupby
	# test/transcoder-transform
)

