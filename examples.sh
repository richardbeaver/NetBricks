#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
	# ZCSI examples
	# test/lpm
	# test/nat
	# test/acl-fw
	# test/maglev
	test/chain-test
	# PVN application
	# test/app-tlsv_t
	# test/app-rdr_t
	# test/app-p2p_t
	# test/app-xcdr_t
	# PVN NF libraries
	# pvnf/tlsv
	# pvnf/rdr
	# pvnf/p2p
	# pvnf/xcdr
	# PVN chain
	# test/co-tlsv-rdr
	# test/co-rdr-p2p
	# test/co-rdr-xcdr
	# test/co-tlsv-p2p
	# test/co-tlsv-xcdr
	# test/co-xcdr-p2p
	# New coresident NFs
	# test/co-rdr-xcdr-p2p
	# test/co-tlsv-rdr-p2p
	# test/co-tlsv-p2p-xcdr
	# test/co-tlsv-rdr-xcdr
	# test/co-tlsv-rdr-p2p-xcdr
)
