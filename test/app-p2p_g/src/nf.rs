use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::measure::*;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::{ipv4_extract_flow, Flow};
use fnv::FnvHasher;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use transmission::{Client, ClientConfig};

#[derive(Clone, Default)]
struct Unit;

#[derive(Clone, Copy, Default)]
struct FlowUsed {
    pub flow: Flow,
    pub time: u64,
    pub used: bool,
}

type FnvHash = BuildHasherDefault<FnvHasher>;

pub fn p2p<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // Measurement code
    //
    // NOTE: Store timestamps and calculate the delta to get the processing time for individual
    // packet is disabled here (TOTAL_MEASURED_PKT removed)

    // start timestamps will be a vec protected with arc and mutex.
    let start_ts = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));
    let mut stop_ts_not_matched: HashMap<usize, Instant> = HashMap::with_capacity(EPSILON);
    let stop_ts_matched = Arc::new(Mutex::new(Vec::<Instant>::with_capacity(EPSILON)));

    let t1_2 = Arc::clone(&start_ts);
    let t1_1 = Arc::clone(&start_ts);
    let t2_1 = Arc::clone(&stop_ts_matched);
    let t2_2 = Arc::clone(&stop_ts_matched);

    // pkt count
    let mut pkt_count = 0;

    // Workload
    let workload = "/home/jethros/dev/netbricks/test/p2p/workloads/20_workload.json";
    // let workload = "/home/jethros/dev/netbricks/test/p2p/workloads/1_workload.json";
    let mut workload = load_json(workload.to_string());

    // Fixed transmission setup
    let torrents_dir = "/home/jethros/dev/netbricks/test/p2p/torrent_files/";
    // let workload = "p2p-workload.json";
    // 1, 10, 20, 40, 50, 75, 100, 150, 200

    let config_dir = "/data/config";
    let download_dir = "/data/downloads";

    // let config_dir = "config";
    // let download_dir = "downloads";
    let config = ClientConfig::new()
        .app_name("testing")
        .config_dir(config_dir)
        .use_utp(false)
        .download_dir(download_dir);
    let c = Client::new(config);

    let mut pivot = 0 as u64;
    let now = Instant::now();

    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .transform(box move |p| {
            pkt_count += 1;

            if pkt_count > NUM_TO_IGNORE {
                let mut w = t1_1.lock().unwrap();
                let start = Instant::now();
                // w.push(start);
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
                let match_ip = 180_907_852 as u32;
                // https://wiki.wireshark.org/BitTorrent
                let match_port = vec![6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 6969];

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
                    if *src_ip == match_ip && match_port.contains(&dst_port) {
                        // println!("pkt count: {:?}", pkt_count);
                        // println!("We got a hit\n src ip: {:?}, dst port: {:?}", src_ip, dst_port);
                        matched = true
                    } else if *dst_ip == match_ip && match_port.contains(&src_port) {
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
                    let stop = Instant::now();
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
        .transform(box move |_| {
            if now.elapsed().as_secs() == pivot {
                // run_transcode(pivot);
                run_torrent(pivot, &mut workload, torrents_dir, &c);
                // println!("pivot: {:?}", pivot);
                pivot = now.elapsed().as_secs() + 1;
            }

            pkt_count += 1;
            // println!("pkt count {:?}", pkt_count);

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
