use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::{ipv4_extract_flow, Flow};
use fnv::FnvHasher;
use headless_chrome::Browser;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EPSILON: usize = 1000;
const NUM_TO_IGNORE: usize = 0;
const TOTAL_MEASURED_PKT: usize = 300_000_000;
const MEASURE_TIME: u64 = 60;

#[derive(Clone, Default)]
struct Unit;
#[derive(Clone, Copy, Default)]
struct FlowUsed {
    pub flow: Flow,
    pub time: u64,
    pub used: bool,
}

type FnvHash = BuildHasherDefault<FnvHasher>;

pub fn rdr_nat<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
    nat_ip: &Ipv4Addr,
) -> CompositionBatch {
    // Measurement code

    // pkt count
    let mut pkt_count = 0;

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts_1 = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let stop_ts_non_tcp = Arc::new(Mutex::new(HashMap::<usize, Instant>::with_capacity(
        TOTAL_MEASURED_PKT + EPSILON,
    )));
    let mut stop_ts_tcp: Vec<Instant> = Vec::with_capacity(TOTAL_MEASURED_PKT + EPSILON);

    let t1_1 = Arc::clone(&start_ts_1);
    let t1_2 = Arc::clone(&start_ts_1);
    let t2_1 = Arc::clone(&stop_ts_non_tcp);
    let t2_2 = Arc::clone(&stop_ts_non_tcp);

    // NAT
    let ip = u32::from(*nat_ip);
    let mut port_hash = HashMap::<Flow, Flow, FnvHash>::with_capacity_and_hasher(65536, Default::default());
    let mut flow_vec: Vec<FlowUsed> = (MIN_PORT..65535).map(|_| Default::default()).collect();
    let mut next_port = 1024;
    const MIN_PORT: u16 = 1024;
    const MAX_PORT: u16 = 65535;

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Workloads:

    // let workload_path = "workloads/current_workload.json";
    // let num_of_users = 140;
    // let num_of_secs = 2000;

    let workload_path = "/home/jethros/dev/netbricks/test/rdr-nat-groupby/workloads/simple_workload.json";
    let num_of_users = 20;
    let num_of_secs = 100;

    // println!("DEBUG: workload path {:?}", workload_path);
    let mut workload = load_json(workload_path.to_string(), num_of_users, num_of_secs).unwrap();
    // println!("DEBUG: json to workload is done",);

    // Browser list.
    let mut browser_list: Vec<Browser> = Vec::new();

    for _ in 0..num_of_users {
        let browser = browser_create().unwrap();
        browser_list.push(browser);
    }
    // println!("All browsers are created ",);

    // Jobs stack.
    let mut job_stack = Vec::new();
    let mut pivot = 0 as u64;
    for i in (1..num_of_secs).rev() {
        job_stack.push(i);
    }
    // println!("job stack: {:?}", job_stack);
    // println!("Job stack is created",);

    // log msg are printed twice
    // FIXME

    let now = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |_| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                w.push(Instant::now());
            }
        })
        .parse::<MacHeader>()
        .transform(box move |pkt| {
            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            // let hdr = pkt.get_mut_header();
            let payload = pkt.get_mut_payload();
            if let Some(flow) = ipv4_extract_flow(payload) {
                let found = match port_hash.get(&flow) {
                    Some(s) => {
                        s.ipv4_stamp_flow(payload);
                        true
                    }
                    None => false,
                };
                if !found {
                    if next_port < MAX_PORT {
                        let assigned_port = next_port; //FIXME.
                        next_port += 1;
                        flow_vec[assigned_port as usize].flow = flow;
                        flow_vec[assigned_port as usize].used = true;
                        let mut outgoing_flow = flow.clone();
                        outgoing_flow.src_ip = ip;
                        outgoing_flow.src_port = assigned_port;
                        let rev_flow = outgoing_flow.reverse_flow();

                        port_hash.insert(flow, outgoing_flow);
                        port_hash.insert(rev_flow, flow.reverse_flow());

                        outgoing_flow.ipv4_stamp_flow(payload);
                    }
                }
            }
        })
        .parse::<IpHeader>()
        .group_by(
            2,
            box move |p| {
                pkt_count += 1;
                if p.get_header().protocol() == 6 {
                    0
                } else {
                    if pkt_count > NUM_TO_IGNORE {
                        let mut w = t2_1.lock().unwrap();
                        w.insert(pkt_count - NUM_TO_IGNORE, Instant::now());
                    }
                    1
                }
            },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
        .parse::<TcpHeader>()
        .transform(box move |pkt| {
            // Scheduling browsing jobs.
            //
            if now.elapsed().as_secs() == pivot {
                let current_work = match workload.pop() {
                    Some(t) => t,
                    None => return,
                };
                simple_scheduler(&pivot, &num_of_users, current_work, &browser_list);
                pivot = job_stack.pop().unwrap() as u64;
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            if pkt_count == NUM_TO_IGNORE {
                println!("\nMeasurement started ",);
                println!(
                    "NUM_TO_IGNORE: {:#?}, TOTAL_MEASURED_PKT: {:#?}, pkt_count: {:#?}",
                    NUM_TO_IGNORE, TOTAL_MEASURED_PKT, pkt_count
                );
            }

            if now.elapsed().as_secs() == MEASURE_TIME {
                println!("pkt count {:?}", pkt_count);
                // let mut total_duration = Duration::new(0, 0);
                let mut total_time1 = Duration::new(0, 0);
                let w1 = t1_2.lock().unwrap();
                let w2 = t2_2.lock().unwrap();
                println!(
                    "# of start ts\n w1 {:#?}, hashmap {:#?}, # of stop ts: {:#?}",
                    w1.len(),
                    w2.len(),
                    stop_ts_tcp.len(),
                );
                let actual_stop_ts = merge_ts(pkt_count - 1, stop_ts_tcp.clone(), w2.clone());
                let num = actual_stop_ts.len();
                println!(
                    "stop ts tcp len: {:?}, actual_stop_ts len: {:?}",
                    stop_ts_tcp.len(),
                    actual_stop_ts.len()
                );
                println!("Detailed Latency Result start: {:?}", num);
                for i in 0..num {
                    let stop = actual_stop_ts.get(&i).unwrap();
                    let since_the_epoch1 = stop.checked_duration_since(w1[i]).unwrap();
                    // print!("{:?}, ", since_the_epoch1);
                    total_time1 = total_time1 + since_the_epoch1;
                }
                println!("\nDetailed Latency Result end",);
                println!(
                    "Latency Result: avg processing time 1 is {:?}",
                    total_time1 / num as u32
                );
            }

            if pkt_count > NUM_TO_IGNORE {
                let end = Instant::now();
                stop_ts_tcp.push(end);
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
