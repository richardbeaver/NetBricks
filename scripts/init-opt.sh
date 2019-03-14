#!/bin/bash
export LD_LIBRARY_PATH=/opt/dev/netbricks/3rdparty/dpdk/build/lib
DPDK_HOME=/opt/dev/netbricks/3rdparty/dpdk
modprobe uio
insmod $DPDK_HOME/build/kmod/igb_uio.ko
$DPDK_HOME/usertools/dpdk-devbind.py -b igb_uio 01:00.{0,1}
