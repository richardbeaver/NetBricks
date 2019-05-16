#!/bin/bash

# NOTE: This is the script that should be used to setup the environment. Also
# note that you might need to recompile NetBricks if a system update happened.

set -euo pipefail
set -x

export LD_LIBRARY_PATH=$HOME/dev/netbricks/3rdparty/dpdk/build/lib
BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
DPDK_HOME=$BASE_DIR/../3rdparty/dpdk

modprobe uio
insmod $DPDK_HOME/build/kmod/igb_uio.ko

sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"

$DPDK_HOME/usertools/dpdk-devbind.py --status \
			| grep XL710 \
			| awk '{print $1}' \
			| xargs \
			$DPDK_HOME/usertools/dpdk-devbind.py --bind=igb_uio
