#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=zcsi-chain
M_CORE=0
CHAIN_LEN=1
START_POS=0

#PORT_OPTIONS="dpdk:eth_pcap0,rx_pcap=data/http_lemmy.pcap,tx_pcap=/tmp/out.pcap"
PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"
#-c 2 -c 3 -c 4 -c 5  \

../../build.sh run $NF_NAME -n "The naive $CHAIN_LEN chained NF in NetBricks..." -m $M_CORE  \
    -l $CHAIN_LEN -j $START_POS  \
    -c 2   \
    -p $PORT_ONE -p $PORT_TWO
