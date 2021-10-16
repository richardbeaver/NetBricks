#!/bin/bash

#set -x
set -euo pipefail

export RUST_BACKTRACE=full
NF_NAME=pvn-tlsv-transform-app
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n " =========== Running TLS Validator ============  " -m $M_CORE  \
    -c 4 -c 5 \
    -p $PORT_ONE -p $PORT_TWO
