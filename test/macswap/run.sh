#!/bin/bash
#set -x
set -euo pipefail

# Weird

NF_NAME=macswap
M_CORE=0

#PORT_OPTIONS="dpdk:eth_pcap0,rx_pcap=data/http_lemmy.pcap,tx_pcap=/tmp/out.pcap"
PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

#../../build.sh run $NF_NAME -n "LPM testing" -m $M_CORE -c $CORES -p $PORT_OPTIONS
../../build.sh run $NF_NAME -n "MAC swaping" -m $M_CORE -c 2 -c 3 -c 4 -c 5 -p $PORT_ONE -p $PORT_TWO 1000
