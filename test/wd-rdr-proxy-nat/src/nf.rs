// use self::utils::{browser_create, load_json, user_browse};
use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::{ipv4_extract_flow, Flow};
use fnv::FnvHasher;
use headless_chrome::Browser;
use job_scheduler::{Job, JobScheduler};
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const EPSILON: usize = 1000;
const NUM_TO_IGNORE: usize = 0;
const TOTAL_MEASURED_PKT: usize = 800_000_000;
const MEASURE_TIME: u64 = 120;

#[derive(Clone, Default)]
struct Unit;
#[derive(Clone, Copy, Default)]
struct FlowUsed {
    pub flow: Flow,
    pub time: u64,
    pub used: bool,
}

type FnvHash = BuildHasherDefault<FnvHasher>;

pub fn rdr_proxy<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
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

    let workload_path = "/home/jethros/dev/netbricks/test/wd-rdr-proxy/workloads/one.json";
    let num_of_users = 1;
    let num_of_secs = 100;
    println!("DEBUG: workload path {:?}", workload_path);

    // let workload_path = "workloads/current_workload.json";
    // let num_of_users = 140;
    // let num_of_secs = 2000;

    // let workload_path = "/home/jethros/dev/netbricks/test/wd-rdr-proxy/workloads/simple_workload.json";
    // let num_of_users = 20;
    // let num_of_secs = 100;
    // println!("DEBUG: workload path {:?}", workload_path);

    // Browser list.
    let mut browser_list: Vec<Browser> = Vec::new();

    let workload = load_json(workload_path.to_string(), num_of_users, num_of_secs).unwrap();
    println!("DEBUG: json to workload is done",);

    for _ in 0..num_of_users {
        let browser = browser_create().unwrap();
        browser_list.push(browser);
    }
    println!("All browsers are created ",);

    let now = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |p| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                w.push(Instant::now());
            }
        })
        .parse::<MacHeader>()
        .transform(box move |p| {
            p.get_mut_header();
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
        .transform(box move |_| {
            let mut sched = JobScheduler::new();
            let mut iterator = workload.iter();
            let mut count = 0;

            sched.add(Job::new("1/1 * * * * *".parse().unwrap(), || {
                let t = iterator.next();
                count += 1;
                // println!("count: {:?}", count);
                match t {
                    Some(current_work) => {
                        // println!("current work {:?}", current_work);
                        for current_user in 1..num_of_users + 1 {
                            // println!("{:?}", current_work[&current_user]);
                            // println!("current_user {:?}", current_user);
                            async {
                                match user_browse(&browser_list[current_user - 1], current_work[&current_user].clone())
                                    .await
                                {
                                    Ok(_) => {}
                                    Err(e) => println!("User {} caused an error: {:?}", current_user, e),
                                }

                            };
                            // user_browse(&browser_list[current_user], current_work[&current_user].clone());
                        }
                    }
                    None => {
                        println!("Nothing in the work queue, waiting for 30 seconds");
                        thread::sleep(std::time::Duration::new(30, 0));
                    }
                }
            }));

            loop {
                sched.tick();

                std::thread::sleep(Duration::from_millis(500));
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
                println!("Latency results start: {:?}", num);
                for i in 0..num {
                    let stop = actual_stop_ts.get(&i).unwrap();
                    let since_the_epoch1 = stop.checked_duration_since(w1[i]).unwrap();
                    // print!("{:?}, ", since_the_epoch1);
                    total_time1 = total_time1 + since_the_epoch1;
                }
                println!("\nLatency results end",);
                println!("avg processing time 1 is {:?}", total_time1 / num as u32);
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
