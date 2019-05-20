#!/bin/bash

# FIXME: doesn't seem to work

#set -x
set -euo pipefail

NF_NAME=zcsi-tcprecon
M_CORE=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "Tcpdump in NetBricks: " -m $M_CORE  \
    -c 2 -c 3 -c 4 -c 5  \
    -p $PORT_ONE -p $PORT_TWO | tee output
