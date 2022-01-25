//! A P2P network function that uses BitTorrenting to peer and download content. The implementation
//! contains a few ways to execute the logic but the running one is within a controlled peering
//! environment, i.e., a seeder node and three leecher nodes (maybe more) are running beside the NF
//! peering the content. The seeder is configured to be a private tracker and all the nodes are
//! within the same LAN so it guarantees that the peering only happens with our nodes.
#![feature(box_syntax)]
#![feature(asm)]
extern crate crossbeam;
extern crate e2d2;
extern crate failure;
extern crate rshttp;
extern crate rustc_serialize;
extern crate serde_json;
extern crate sha1;
extern crate time;
extern crate tiny_http;

use crate::utils::*;
use e2d2::allocators::CacheAligned;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::operators::ReceiveBatch;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::pvn::measure::*;
use e2d2::pvn::p2p::{p2p_fetch_workload, p2p_load_json, p2p_read_rand_seed, p2p_read_type, p2p_retrieve_param};
use e2d2::scheduler::Scheduler;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::runtime::Runtime;

pub mod utils;

pub fn p2p<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // setup for this run
    let param = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let num_of_torrents = p2p_retrieve_param("/home/jethros/setup".to_string()).unwrap();
    let p2p_type = p2p_read_type("/home/jethros/setup".to_string()).unwrap();

    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)
    let mut metric_exec = true;

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    let torrents_dir = "/home/jethros/dev/pvn/utils/workloads/torrent_files/";

    // pkt count
    let mut pkt_count = 0;

    let _pivot = 0 as usize;
    let now = Instant::now();
    let mut start = Instant::now();

    let mut workload_exec = true;

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    let mut groups = parent
        .transform(box move |_p| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let start = Instant::now();
                if param.inst {
                    w.push(start);
                }
            }
        })
        .parse::<MacHeader>()
        .parse::<IpHeader>()
        .metadata(box move |p| {
            let f = p.get_header().flow();
            match f {
                Some(f) => f,
                None => fake_flow(),
            }
        })
        .parse::<TcpHeader>()
        .group_by(
            2,
            box move |p| {
                pkt_count += 1;
                let f = p.read_metadata();

                let mut matched = false;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_ip = 180_907_852 as u32;
                // https://wiki.wireshark.org/BitTorrent
                let match_port = vec![6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

                if f.proto == 6
                    && ((f.src_ip == match_ip && match_port.contains(&f.src_port))
                        || (f.dst_ip == match_ip && match_port.contains(&f.dst_port)))
                {
                    matched = true
                }

                if now.elapsed().as_secs() >= param.expr_time && metric_exec {
                    if param.inst {
                        println!("pkt count {:?}", pkt_count);
                        let w1 = t1_2.lock().unwrap();
                        let w2 = t2_2.lock().unwrap();
                        println!(
                            "# of start ts\n w1 {:#?}, hashmap {:#?}, # of stop ts: {:#?}",
                            w1.len(),
                            stop_ts_not_matched.len(),
                            w2.len(),
                        );
                        let actual_stop_ts = merge_ts(pkt_count - 1, w2.clone(), stop_ts_not_matched.clone());
                        let num = actual_stop_ts.len();
                        println!(
                            "stop ts matched len: {:?}, actual_stop_ts len: {:?}",
                            w2.len(),
                            actual_stop_ts.len()
                        );
                        println!("Latency results start: {:?}", num);
                        let mut tmp_results = Vec::<u128>::with_capacity(num);
                        for i in 0..num {
                            let stop = actual_stop_ts.get(&i).unwrap();
                            let since_the_epoch = stop.checked_duration_since(w1[i]).unwrap();
                            tmp_results.push(since_the_epoch.as_nanos());
                            // print!("{:?}, ", since_the_epoch1);
                            // total_time1 = total_time1 + since_the_epoch1;
                        }
                        compute_stat(tmp_results);
                        println!("\nLatency results end",);
                    }
                    metric_exec = false;
                }

                if pkt_count > NUM_TO_IGNORE && !matched {
                    let stop = Instant::now();
                    if param.inst {
                        stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, stop);
                    }
                }

                if matched {
                    0
                } else {
                    1
                }
            },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .transform(box move |_| {
            if workload_exec {
                // Workload
                let fp_workload = p2p_fetch_workload("/home/jethros/setup".to_string()).unwrap();

                println!("p2p type: {}", p2p_type);
                println!("match p2p controlled before btrun");
                let p2p_torrents =
                    p2p_read_rand_seed(num_of_torrents, param.iter.to_string(), "p2p_controlled".to_string()).unwrap();

                let _ = bt_run_torrents(p2p_torrents);

                println!("bt run is not blocking");
                // workload_exec = false;

                workload_exec = false;
            }

            if start.elapsed().as_secs() >= 1 as u64 {
                start = Instant::now();
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                if param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}

/// Test for the p2p downloader network function to schedule pipelines.
pub fn p2p_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
    for port in &ports {
        println!(
            "Receiving port {} rxq {} txq {}",
            port.port.mac_address(),
            port.rxq(),
            port.txq()
        );
    }

    // create a pipeline for each port
    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| p2p(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}
