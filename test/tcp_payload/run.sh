#!/bin/bash


#set -x
set -euo pipefail

NF_NAME=tcp_payload
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "Tcpdump in NetBricks: " -m $M_CORE  \
    -c 4 -c 5 -c 6 -c 7 -c 8 \
    -p $PORT_ONE -p $PORT_TWO | tee output
