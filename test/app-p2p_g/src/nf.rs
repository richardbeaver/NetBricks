use crate::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::measure::*;
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transmission::{Client, ClientConfig};

pub fn p2p<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // setup for this run
    let setup_val = read_setup("/home/jethros/setup".to_string()).unwrap();
    let p2p_param = p2p_retrieve_param(setup_val.parse::<usize>().unwrap()).unwrap();

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

    // Workload
    let workload = p2p_fetch_workload(setup_val.parse::<usize>().unwrap()).unwrap();
    let mut workload = load_json(workload.to_string());

    // Fixed transmission setup
    let torrents_dir = "/home/jethros/dev/pvn-utils/workload/torrent_files/";

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

    let mut pivot = 0 as usize;
    let now = Instant::now();
    let mut start = Instant::now();

    let mut torrent_list = Vec::new();

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
                        // print!("{:?}, ", since_the_epoch1);
                        // total_time1 = total_time1 + since_the_epoch1;
                    }
                    compute_stat(tmp_results);
                    println!("\nLatency results end",);
                    // println!("avg processing time 1 is {:?}", total_time1 / num as u32);
                }

                if pkt_count > NUM_TO_IGNORE && !matched {
                    let stop = Instant::now();
                    // stop_ts_not_matched.insert(pkt_count - NUM_TO_IGNORE, stop);
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
            while let Some(torrent) = workload.pop() {
                if pivot >= p2p_param {
                    break;
                }
                println!("torrent is : {:?}", torrent);
                let torrent = torrents_dir.to_owned() + &torrent;
                // println!("torrent dir is : {:?}", torrent_dir);
                let t = c.add_torrent_file(&torrent).unwrap();
                t.start();
                torrent_list.push(t);
                pivot += 1;

                if pivot == p2p_param {
                    let end = Instant::now();
                    // println!(
                    //     "start {:?}, elapsed: {:?}, duration: {:?}",
                    //     start,
                    //     start.elapsed().as_secs(),
                    //     end.duration_since(start)
                    // );
                    // println!("init start");
                    start = Instant::now();
                }
            }

            if start.elapsed().as_secs() >= 1 as u64 {
                let tlist = torrent_list.clone();
                // for t in tlist {
                //     println!(
                //         "state: {:?}, percent complete: {:?}, percent done: {:?}, finished: {:?}, is stalled: {:?}",
                //         t.stats().state,
                //         t.stats().percent_complete,
                //         t.stats().percent_done,
                //         t.stats().finished,
                //         t.stats().is_stalled
                //     );
                // }
                if tlist.into_iter().all(|x| x.stats().percent_done == 1.0) {
                    println!("All Done!!!!!");
                }
                // println!("1 second");
                start = Instant::now();
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
