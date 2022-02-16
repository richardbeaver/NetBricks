#!/bin/bash

#set -x
set -euo pipefail

NF_NAME=zcsi-chain

M_CORE=2
CHAIN_LEN=1
START_POS=0

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -f config.toml
