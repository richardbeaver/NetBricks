//! A TLS validator network function which will identify the TLS handshake messages, extract the
//! certificates from the network traffic, and validate the certificates. The NF can run with a
//! configurable TLS version and enforce the validation of the certs.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate rustls;
extern crate time;
extern crate webpki;
extern crate webpki_roots;
#[macro_use]
extern crate log;

use self::utils::{get_server_name, on_frame, ordered_validate, tlsf_update, unordered_validate};
use e2d2::allocators::CacheAligned;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::interface::*;
use e2d2::operators::merge;
use e2d2::operators::{Batch, CompositionBatch, ReceiveBatch};
use e2d2::pvn::measure::*;
use e2d2::scheduler::Scheduler;

use e2d2::utils::Flow;
use rustls::internal::msgs::handshake::HandshakePayload::{ClientHello, ClientKeyExchange, ServerHello};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub mod utils;

/// Test for the validator network function to schedule pipelines.
pub fn validator_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
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
        .map(|port| validator(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

/// Network function that extracts certificates from sequence of packets and validate the
/// certificates.
///
/// Several data structures are used here to have the TLS validator work. Core issues that we have
/// to address are: 1. Handling reassembling packets in TCP. Note that it is a
/// naive implementation of TCP out-of-order segments, for a more comprehensive version you
/// should visit something like [assembler in
/// smoltcp](https://github.com/m-labs/smoltcp/blob/master/src/storage/assembler.rs) and [ring
/// buffer](https://github.com/m-labs/smoltcp/blob/master/src/storage/ring_buffer.rs#L238-L333). 2.
/// Store packets that could be part of the TLS handshake (that we care about).
// pub fn validator<T: 'static + Batch<Header = NullHeader>>(parent: T)
pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let param = read_setup_param("/home/jethros/setup".to_string()).unwrap();
    let mut metric_exec = true;

    // New payload cache.
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // Temporary payload cache.
    let mut tmp_payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // New map to keep track of the expected seq #
    let mut seqnum_map = HashMap::<Flow, u32>::with_hasher(Default::default());
    // Temporary map to keep track of the expected seq #
    let mut tmp_seqnum_map = HashMap::<Flow, (u32, u32)>::with_hasher(Default::default());
    // TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();
    // DNS name cache.
    let mut name_cache = HashMap::<Flow, webpki::DNSName>::with_hasher(Default::default());

    // Cert count
    let mut cert_count = 0;
    // pkt count
    let mut pkt_count = 0;

    // Measurement code
    //
    // start timestamps will be a vec protected with arc and mutex.
    let start_ts_1 = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let stop_ts_non_tcp = Arc::new(Mutex::new(HashMap::<usize, Instant>::with_capacity(
        TOTAL_MEASURED_PKT + EPSILON,
    )));
    let mut stop_ts_tcp = Arc::new(Mutex::new(Vec::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));

    let t1_1 = Arc::clone(&start_ts_1);
    let t1_2 = Arc::clone(&start_ts_1);
    let t2_1 = Arc::clone(&stop_ts_non_tcp);
    let t2_2 = Arc::clone(&stop_ts_non_tcp);
    let t3_1 = Arc::clone(&stop_ts_tcp);
    let t3_2 = Arc::clone(&stop_ts_tcp);

    let now = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |_| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let end = Instant::now();
                if param.inst {
                    w.push(end);
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
        .group_by(
            2,
            box move |p| {
                pkt_count += 1;
                let f = p.read_metadata();

                // 0 means the packet doesn't match RDR or P2P
                let mut matched = 0;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying

                // Match TLS packets to group 1 and XCDR packets to group 2, the rest to group 0
                if f.proto == 6 {
                    matched = 1;
                } else {
                    if pkt_count > NUM_TO_IGNORE {
                        let mut w = t2_1.lock().unwrap();
                        if param.inst {
                            w.insert(pkt_count - NUM_TO_IGNORE, Instant::now());
                        }
                    }
                }

                if now.elapsed().as_secs() >= param.expr_time && metric_exec {
                    if param.inst {
                        println!("pkt count {:?}", pkt_count);
                        // let mut total_duration = Duration::new(0, 0);
                        let total_time1 = Duration::new(0, 0);
                        let w1 = t1_2.lock().unwrap();
                        let w2 = t2_2.lock().unwrap();
                        let w3 = t3_2.lock().unwrap();
                        println!(
                            "# of start ts\n w1 {:#?}, hashmap {:#?}, # of stop ts: {:#?}",
                            w1.len(),
                            w2.len(),
                            w3.len(),
                        );
                        let actual_stop_ts = merge_ts(pkt_count - 1, w3.clone(), w2.clone());
                        let num = actual_stop_ts.len();
                        println!(
                            "stop ts tcp len: {:?}, actual_stop_ts len: {:?}",
                            w3.len(),
                            actual_stop_ts.len()
                        );

                        println!("Latency results start: {:?}", num);
                        let mut tmp_results = Vec::<u128>::with_capacity(num);
                        for i in 0..num {
                            let stop = actual_stop_ts.get(&i).unwrap();
                            let since_the_epoch = stop.checked_duration_since(w1[i]).unwrap();
                            tmp_results.push(since_the_epoch.as_nanos());
                        }
                        compute_stat(tmp_results);
                        println!("\nLatency results end",);
                    }

                    metric_exec = false;
                }

                matched
            },
            sched,
        );

    let tlsv_pipe = groups
        .get_group(1)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
        .parse::<TcpHeader>()
        .transform(box move |p| {
            let flow = p.read_metadata();
            let rev_flow = flow.reverse_flow();
            let _seq = p.get_header().seq_num();
            let _tcph = p.get_header();
            let _payload_size = p.payload_size();

            // FIXME: The else part should be written as a filter and it should exec before all these..
            if !unsafe_connection.contains(flow) {
                // check if the flow is recognized
                if payload_cache.contains_key(flow) {
                    // The rest of the TLS server hello handshake should be captured here.
                    // Check if this packet is not expected, ie, is a out of order segment.
                    match _seq.cmp(seqnum_map.get(&flow).unwrap()) {
                        Ordering::Equal => {
                            // We received an expected packet
                            //debug!("{:?}", p.get_payload());
                            tlsf_update(payload_cache.entry(*flow), &p.get_payload());
                            seqnum_map.entry(*flow).and_modify(|e| {
                                *e += _payload_size as u32;
                            });
                        }
                        Ordering::Greater => {
                            // We received a out-of-order TLS segment
                            // We need to check if we should update the entry in the tmp payload cache
                            if tmp_payload_cache.contains_key(flow) {
                                // Check if we should update the entry in the tmp payload cache
                                let (_, entry_expected_seqno) = *tmp_seqnum_map.get(flow).unwrap();
                                if _seq == entry_expected_seqno {
                                    tlsf_update(tmp_payload_cache.entry(*flow), &p.get_payload());
                                    tmp_seqnum_map.entry(*flow).and_modify(|(_, entry_expected_seqno)| {
                                        *entry_expected_seqno += _payload_size as u32;
                                    });
                                } else {
                                }
                            } else {
                                tmp_seqnum_map.insert(*flow, (_seq, _seq + _payload_size as u32));
                                tmp_payload_cache.insert(*flow, p.get_payload().to_vec());
                            }
                        }
                        Ordering::Less => {}
                    }
                } else {
                    match on_frame(&p.get_payload()) {
                        Some((handshake, _)) => {
                            match handshake.payload {
                                ClientHello(_) => {
                                    let server_name = match get_server_name(&p.get_payload()) {
                                        Some(n) => n,
                                        None => {
                                            // FIXME: tmp hack
                                            let name_ref =
                                                webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
                                            webpki::DNSName::from(name_ref)
                                        }
                                    };
                                    name_cache
                                        .entry(rev_flow)
                                        .and_modify(|e| *e = server_name.clone())
                                        .or_insert(server_name);
                                }
                                ServerHello(_) => {
                                    // capture the sequence number
                                    seqnum_map.insert(*flow, _seq + _payload_size as u32);
                                    payload_cache.insert(*flow, p.get_payload().to_vec());
                                }
                                ClientKeyExchange(_) => {
                                    let dns_name = name_cache.remove(&rev_flow);
                                    match dns_name {
                                        Some(name) => {
                                            if tmp_payload_cache.contains_key(&rev_flow) {
                                                unordered_validate(
                                                    name,
                                                    &flow,
                                                    &mut cert_count,
                                                    &mut unsafe_connection,
                                                    &mut tmp_payload_cache,
                                                    &mut tmp_seqnum_map,
                                                    &mut payload_cache,
                                                    &mut seqnum_map,
                                                )
                                            } else {
                                                ordered_validate(
                                                    name,
                                                    &flow,
                                                    &mut cert_count,
                                                    &mut unsafe_connection,
                                                    &mut payload_cache,
                                                    &mut seqnum_map,
                                                )
                                            }
                                        }
                                        None => {} //eprintln!("We are missing the dns name from the client hello",),
                                    }
                                }
                                _ => {} //eprintln!("Other kinds of payload",),
                            }
                        }
                        None => {} // eprintln!("Get none for matching payload",),
                    }
                }
            } else {
                // Disabled for now, we can enable it when we are finished.

                // info!("Pkt #{} belong to a unsafe flow!\n", _seq);
                // info!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                // let _ = unsafe_connection.take(flow);
                // let tcph = p.get_mut_header();
                // tcph.set_rst_flag();
            }

            pkt_count += 1;

            if pkt_count == NUM_TO_IGNORE {
                println!("\nMeasurement started ",);
                println!(
                    "NUM_TO_IGNORE: {:#?}, TOTAL_MEASURED_PKT: {:#?}, pkt_count: {:#?}",
                    NUM_TO_IGNORE, TOTAL_MEASURED_PKT, pkt_count
                );
            }

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t3_1.lock().unwrap();
                let end = Instant::now();
                if param.inst {
                    w.push(end);
                }
            }
        })
        .reset()
        .compose();

    merge(vec![groups.get_group(0).unwrap().compose(), tlsv_pipe]).compose()
}
