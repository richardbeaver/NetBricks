#!/bin/bash

#set -x
set -euo pipefail

TEST_NAME=zcsi-delay
M_CORE=0
CORES="1-4"
PORT_OPTIONS="dpdk:eth_pcap0,rx_pcap=data/http_lemmy.pcap,tx_pcap=/tmp/out.pcap"

../../build.sh run zcsi-test -m $M_CORE $CORES --secondary
