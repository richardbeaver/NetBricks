use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::measure::*;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::{ipv4_extract_flow, Flow};
use headless_chrome::Browser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn rdr<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let setup_val = read_setup("/home/jethros/setup".to_string()).unwrap();
    let rdr_users = rdr_retrieve_users(setup_val.parse::<usize>().unwrap()).unwrap();
    let iter_val = read_iter("/home/jethros/setup".to_string()).unwrap();

    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    // Pkt counter. We keep track of every packet.
    let mut pkt_count = 0;

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Workloads:
    // let workload_path = "/home/jethros/dev/pvn/utils/workloads/rdr_pvn_workloads/rdr_pvn_workload_".to_owned()
    //     + &iter_val.to_string()
    //     + ".json";
    // let num_of_users = 100;
    let workload_path = "/home/jethros/dev/pvn/utils/workloads/rdr_pvn_workloads/rdr_pvn_workload_5.json";
    let num_of_users = rdr_users;

    let num_of_secs = 600;

    let mut rdr_workload = rdr_load_workload(workload_path.to_string(), num_of_secs, num_of_users).unwrap();
    println!("Workload is generated",);

    // Browser list.
    let mut browser_list: Vec<Browser> = Vec::new();

    for x in 0..num_of_users {
        // println!("{:?}",x );
        let browser = browser_create().unwrap();
        browser_list.push(browser);
    }
    println!("{} browsers are created ", num_of_users);

    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut elapsed_time: Vec<u128> = Vec::new();

    let mut pivot = 1;
    let now = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |_| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let end = Instant::now();
                // w.push(end;
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
                let match_ip = 3_232_235_524 as u32;
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
                        matched = true
                    } else if *dst_ip == match_ip && src_port == match_port {
                        matched = true
                    }
                }
                if now.elapsed().as_secs() == APP_MEASURE_TIME {
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
                    }
                    compute_stat(tmp_results);
                    println!("\nLatency results end",);
                }

                if pkt_count > NUM_TO_IGNORE && !matched {
                    let end = Instant::now();
                    // stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
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
            let mut num_of_visits = Vec::new();
            let mut elapsed_time = Vec::new();

            // Scheduling browsing jobs.
            // FIXME: This is not ideal as we are not actually schedule browse.
            let cur_time = now.elapsed().as_secs() as usize;
            if rdr_workload.contains_key(&cur_time) {
                println!("pivot {:?}", cur_time);
                let min = cur_time / 60;
                let rest_sec = cur_time % 60;
                println!("{:?} min, {:?} second", min, rest_sec);
                match rdr_workload.remove(&cur_time) {
                    Some(wd) => {
                        let (visits, elapsed) = rdr_scheduler_ng(&cur_time, wd, &browser_list).unwrap();
                        num_of_visits.push(visits);
                        elapsed_time.push(elapsed);
                    }
                    None => println!("No workload for second {:?}", cur_time),
                }
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

            // Measurement: metric for the performance of the RDR proxy
            if now.elapsed().as_secs() == APP_MEASURE_TIME {
                let total_visits: usize = num_of_visits.iter().sum();
                let total_time: usize = elapsed_time.iter().sum();
                println!(
                    "Metric: num_of_visit: {:?}, total_elapsed_time: {:?}",
                    total_visits, total_time
                );
            }

            // Measurement: instrumentation to collect latency metrics
            if pkt_count > NUM_TO_IGNORE {
                let mut w = t2_1.lock().unwrap();
                let end = Instant::now();
                // w.push(end);
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
