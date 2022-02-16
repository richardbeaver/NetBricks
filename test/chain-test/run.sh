#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=zcsi-chain

M_CORE=0
CHAIN_LEN=1
START_POS=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "The naive $CHAIN_LEN chained NF in NetBricks..." \
    -l $CHAIN_LEN  -m $M_CORE \
    -p $PORT_ONE -c 1 \
    -p $PORT_TWO -c 2
