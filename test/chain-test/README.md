Using Cargo from /home/jethros/.cargo/bin/cargo
[sudo] password for jethros:
Going to start with configuration Configuration: name: zcsi mempool size: 3072 core cache: 32 primary core: 0
 Ports:
        Port 0000:01:00.0 RXQ_Count: 1 RX_Queues: [ 1 ] TXQ_Count: 1 TX_Queues: 1 RXD: 128 TXD: 128 Loopback false
        Port 0000:01:00.1 RXQ_Count: 1 RX_Queues: [ 2 ] TXQ_Count: 1 TX_Queues: 2 RXD: 128 TXD: 128 Loopback false
Cores:
        0
        1
        2
        3
Duration: 200

[PortConfiguration { name: "0000:01:00.0", rx_queues: [1], tx_queues: [1], rxd: 128, txd: 128, loopback: false, tso: false, csum: false }, PortConfiguration { name: "0000:01:00.1", rx_queues: [2], tx_queues: [2], rxd: 128, txd: 128, loopback: false, tso: false, csum: false }]
Failed to detect # of NUMA nodes from: /sys/devices/system/node/possible. Assuming a single-node system...
EAL: Detected 6 lcore(s)
EAL: Probing VFIO support...
Running on node 0
Devname: "0000:01:00.0"
EAL: PCI device 0000:01:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 8086:1583 net_i40e
Going to try and use port 0
Devname: "0000:01:00.1"
EAL: PCI device 0000:01:00.1 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 8086:1583 net_i40e
Going to try and use port 1
Running on node 0
Running on node 0
Running on node 0
Running on node 0
Receiving started port: f8:f2:1e:2e:9c:50 (0) rxq: 0 txq: 0
Receiving port port: f8:f2:1e:2e:9c:50 (0) rxq: 0 txq: 0 on chain len 1 pos 0
Running 1 pipelines
Receiving started port: f8:f2:1e:2e:9c:51 (1) rxq: 0 txq: 0
thread 'Receiving port port: f8:f2:1e:2e:9c:51 (1) rxq: 0 txq: 0 on chain len 1 pos 0
sched-3' panicked at 'Running 1 pipelines
index out of bounds: the len is 0 but the index is 0', test/chain-test/src/main.rs:36:38
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
Starting scheduler on 1
thread 'sched-0' panicked at 'index out of bounds: the len is 0 but the index is 0', test/chain-test/src/main.rs:36:38
thread 'main' panicked at 'called `Result::unwrap()` on an `Err` value: "SendError(..)"', framework/src/scheduler/context.rs:164:53
Scheduler exiting sched-2

