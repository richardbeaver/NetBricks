#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=pvn-rdr-transform-app
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run-full $NF_NAME -n "\n=========== Running RDR Proxy============\n" -m $M_CORE  \
    -c 4 -c 5  \
    -p $PORT_ONE -p $PORT_TWO | tee trace.out
