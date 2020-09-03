use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, UdpHeader};
use e2d2::operators::{Batch, CompositionBatch};
use e2d2::pvn::measure::{compute_stat, merge_ts, APP_MEASURE_TIME, EPSILON, NUM_TO_IGNORE, TOTAL_MEASURED_PKT};
use e2d2::pvn::xcdr::{pvn_elapsed, xcdr_read_setup, xcdr_retrieve_param};
use e2d2::scheduler::Scheduler;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub fn transcoder<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let mut metric_exec = true;
    let mut latencyv = Vec::<u128>::new();
    println!("Latency vec uses millisecond");

    // Specific setup config for this run

    // setup for this run
    let (setup_val, port, expr_num) = xcdr_read_setup("/home/jethros/setup".to_string()).unwrap();
    let time_span = xcdr_retrieve_param(setup_val).unwrap();
    println!("Setup: {:?} port: {:?}", setup_val, port,);

    // faktory job queue
    // FIXME: use port from config
    // let default_faktory_conn = "tcp://localhost:".to_string() + &port;
    let default_faktory_conn = "tcp://localhost:7419".to_string();

    // Measurement code
    //
    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // start timestamps will be a vec protected with arc and mutex.
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    // stop timestamps that didn't match
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);

    // stop timestamps will be a vec protected with arc and mutex.
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let t1_1 = Arc::clone(&start_ts);
    let t1_2 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    // pkt count
    let mut pkt_count = 0;

    // pivot for registering jobs. pivot will be incremented by 1 every second
    let mut pivot = 1 as u128 + time_span;

    let now = Instant::now();
    let mut cur = Instant::now();

    // group packets into MAC, TCP and UDP packet.
    let pipeline = parent
        .transform(box move |p| {
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
        .parse::<UdpHeader>()
        .transform(box move |p| {
            // matched to determine if the incoming packet is from the expected traffic
            let mut matched = false;

            // NOTE: the following ip addr and port are hardcoded based on the trace we are
            // replaying
            let match_src_ip = 3_232_235_524 as u32;
            let match_src_port = 58_111;
            let match_dst_ip = 2_457_012_302 as u32;
            let match_dst_port = 443;

            let (src_ip, dst_ip, proto): (&u32, &u32, &u8) = match p.read_metadata() {
                Some((src, dst, p)) => (src, dst, p),
                None => (&0, &0, &0),
            };

            let src_port = p.get_header().src_port();
            let dst_port = p.get_header().dst_port();

            if *proto == 17 {
                if *src_ip == match_src_ip
                    && src_port == match_src_port
                    && *dst_ip == match_dst_ip
                    && dst_port == match_dst_port
                {
                    matched = true
                } else if *src_ip == match_dst_ip
                    && src_port == match_dst_port
                    && *dst_ip == match_src_ip
                    && dst_port == match_src_port
                {
                    matched = true
                }
            }

            if matched {
                let time_elapsed = pvn_elapsed(setup_val, now).unwrap();

                // Append job within the new second
                if time_elapsed >= pivot {
                    let t = cur.elapsed().as_millis();
                    latencyv.push(t);

                    // println!("append job, time_elapsed: {:?}, pivot: {:?}", time_elapsed, pivot);
                    // append job
                    //
                    // we append a job to the job queue every *time_span*
                    append_job_faktory(pivot, Some(&*default_faktory_conn), &expr_num);
                    cur = Instant::now();
                    pivot += time_span;
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

            if now.elapsed().as_secs() >= APP_MEASURE_TIME && metric_exec == true {
                // report the metrics
                println!("Pivot/time: {:?}", pivot / time_span);
                println!("Metric: {:?}", latencyv);

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
                metric_exec = false;
            }
        });
    pipeline.compose()
}
