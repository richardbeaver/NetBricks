#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=zcsi-chain

M_CORE=2
CHAIN_LEN=1
START_POS=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "The naive $CHAIN_LEN chained NF in NetBricks..." \
    -m $M_CORE -l $CHAIN_LEN   \
    -c 2 -c 3  \
    -p $PORT_ONE -p $PORT_TWO
