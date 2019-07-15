#!/bin/bash

#set -x
set -euo pipefail

export RUST_BACKTRACE=1
NF_NAME=zcsi-maglev
M_CORE=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n " =========== Running ZCSI Maglev ============  " -m $M_CORE  \
    -c 4 -c 5 -c 6 -c 7 -c 8 -c 9 \
    -p $PORT_ONE -p $PORT_TWO  | tee output.out
