#!/bin/bash
#set -x
set -euo pipefail

# Weird

NF_NAME=zcsi-nat
M_CORE=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "NATing" -m $M_CORE \
  -c 4 -c 5 \
  -p $PORT_ONE -p $PORT_TWO
