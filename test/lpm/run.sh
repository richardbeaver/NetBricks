#!/bin/bash

#set -x
set -euo pipefail

TEST_NAME=zcsi-delay
M_CORE=0
CORES="2"
#PORT_OPTIONS="dpdk:eth_pcap0,rx_pcap=data/http_lemmy.pcap,tx_pcap=/tmp/out.pcap"
PORT_OPTIONS="0000:01:00.0"

../../build.sh run zcsi-test -m $M_CORE -c $CORES -p $PORT_OPTIONS
