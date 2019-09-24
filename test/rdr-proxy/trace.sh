#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=pvn-rdr
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run-full $NF_NAME -n "\n=========== Running RDR Proxy============\n" -m $M_CORE  \
    -c 2 -c 3 -c 4 -c 5 -c 6 -c 7 -c 8 -c 9 -c 10 -c 11 \
    -p $PORT_ONE -p $PORT_TWO | tee trace.out
