#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=zcsi-maglev
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n " =========== Running ZCSI Maglev ============  " -m $M_CORE  \
    -c 2 -c 3 -c 4 -c 5  \
    -p $PORT_ONE -p $PORT_TWO 
