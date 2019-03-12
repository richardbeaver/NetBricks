#!/bin/bash
set -x
set -e

DELAY_TEST_ROOT="/opt/dev/netbricks/test/delay-test/target/release"
ZCSI_ROOT=/opt/dev/netbricks
echo "Delaying for " $DELAY
echo "Using intefaces" ${IFACE[@]}
echo "Master core" $MCORE
echo "Receiving core" $RCORE
IF=( "${IFACE[@]/#/-v }" )
CORES=( )
for i in "${!IFACE[@]}"; do
	CORES[$i]="-c $RCORE"
done
$DELAY_TEST_ROOT/zcsi-delay -m $MCORE ${IF[@]} ${CORES[@]}  --secondary -n rte -d $DELAY
