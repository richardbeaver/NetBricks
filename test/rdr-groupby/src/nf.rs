use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::measure::*;
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

pub fn rdr<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // Measurement code

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(TOTAL_MEASURED_PKT + EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(TOTAL_MEASURED_PKT + EPSILON)));

    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    // pkt count
    let mut pkt_count = 0;

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Workloads:

    // let workload_path = "workloads/current_workload.json";
    // let num_of_users = 140;
    // let num_of_secs = 2000;

    let workload_path = "/home/jethros/dev/netbricks/test/rdr-groupby/workloads/simple_workload.json";
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
        .parse::<IpHeader>()
        .metadata(box move |p| {
            let src_ip = p.get_header().src();
            let dst_ip = p.get_header().dst();
            let proto = p.get_header().protocol();

            Some((src_ip, dst_ip, proto))
        })
        .parse::<TcpHeader>()
        .group_by(
            2,
            box move |p| {
                pkt_count += 1;

                let mut matched = false;
                // NOTE: the following ip addr and port are hardcode based on the trace we are
                // replaying
                let match_ip = 180907852 as u32;
                // https://wiki.wireshark.org/BitTorrent
                let match_port = 443;

                let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
                    Some((src, dst, p)) => {
                        // println!("src: {:?} dst: {:}", src, dst); //
                        (src, dst, p)
                    }
                    None => (&0, &0, &0),
                };

                let src_port = p.get_header().src_port();
                let dst_port = p.get_header().dst_port();

                // println!("src: {:?} dst: {:}", src_port, dst_port); //

                if *proto == 6 {
                    if *src_ip == match_ip && dst_port == match_port {
                        // println!("pkt count: {:?}", pkt_count);
                        // println!("We got a hit\n src ip: {:?}, dst port: {:?}", src_ip, dst_port);
                        matched = true
                    } else if *dst_ip == match_ip && src_port == match_port {
                        // println!("pkt count: {:?}", pkt_count);
                        // println!("We got a hit\n dst ip: {:?}, src port: {:?}", dst_ip, src_port); //
                        matched = true
                    }
                }
                if now.elapsed().as_secs() == MEASURE_TIME {
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
                    // println!("avg processing time 1 is {:?}", total_time1 / num as u32);
                }

                if pkt_count > NUM_TO_IGNORE && !matched {
                    stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, Instant::now());
                }
                // println!("{:?}", matched);

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

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                w.push(Instant::now());
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
