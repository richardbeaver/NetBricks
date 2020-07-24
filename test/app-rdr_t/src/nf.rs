use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::measure::*;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use headless_chrome::Browser;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn rdr<T: 'static + Batch<Header = NullHeader>>(parent: T, _s: &mut dyn Scheduler) -> CompositionBatch {
    println!("/home/jethros/setup");
    let iter_val = read_iter("/home/jethros/setup".to_string()).unwrap();
    println!("after");

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

    // pkt count
    let mut pkt_count = 0;

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Workloads:
    let workload_path = "/home/jethros/dev/pvn/utils/workloads/rdr_pvn_workloads/rdr_pvn_workload_".to_owned()
        + &iter_val.to_string()
        + ".json";
    println!("{:?}", workload_path);
    let num_of_users = 100;
    let num_of_secs = 600;

    let mut rdr_workload = rdr_load_workload(workload_path.to_string(), num_of_secs, num_of_users).unwrap();
    println!("Workload is generated",);
    // println!("{:?}", rdr_workload);

    // Browser list.
    let mut browser_list: Vec<Browser> = Vec::new();

    for x in 0..num_of_users {
        // println!("x: {:?}", x);
        let browser = browser_create().unwrap();
        browser_list.push(browser);
    }
    println!("All browsers are created ",);

    let mut pivot = 1 as usize;

    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut elapsed_time: Vec<u128> = Vec::new();

    let now = Instant::now();
    println!("Timer started");

    let pipeline = parent
        .transform(box move |_| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let end = Instant::now();
                // w.push(end);
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
        .transform(box move |p| {
            let mut matched = false;
            // NOTE: the following ip addr and port are hardcode based on the trace we are
            // replaying
            // let match_ip = 180_907_852 as u32;
            let match_ip = 3_232_235_524 as u32;
            let match_port = 443;

            let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
                Some((src, dst, p)) => (src, dst, p),
                None => (&0, &0, &0),
            };

            let src_port = p.get_header().src_port();
            let dst_port = p.get_header().dst_port();

            if *proto == 6 {
                if *src_ip == match_ip && dst_port == match_port {
                    matched = true
                } else if *dst_ip == match_ip && src_port == match_port {
                    matched = true
                }
            }

            // Scheduling browsing jobs.
            if matched {
                if now.elapsed().as_secs() == pivot as u64 {
                    let min = pivot / 60;
                    let rest_sec = pivot % 60;
                    println!("{:?} min, {:?} second", min, rest_sec);
                    match rdr_workload.remove(&pivot) {
                        Some(wd) => rdr_scheduler(
                            &pivot,
                            &mut num_of_ok,
                            &mut num_of_err,
                            &mut elapsed_time,
                            &num_of_users,
                            wd,
                            &browser_list,
                        ),
                        None => println!("No workload for second {:?}", pivot),
                    }
                    pivot += 1;
                }

                if pkt_count > NUM_TO_IGNORE {
                    let mut w = t2_1.lock().unwrap();
                    let end = Instant::now();
                    // w.push(end);
                }
            } else {
                if pkt_count > NUM_TO_IGNORE {
                    // Insert the timestamp as
                    let end = Instant::now();
                    // stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, end);
                }
            }

            pkt_count += 1;

            if now.elapsed().as_secs() == APP_MEASURE_TIME {
                println!("pkt count {:?}", pkt_count);

                println!("RDR Scheduling: {:?} {:?}", num_of_ok, num_of_err);
                println!("RDR Elapsed Time: {:?}", elapsed_time);

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
        });
    pipeline.compose()
}
