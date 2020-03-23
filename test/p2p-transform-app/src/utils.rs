use core_affinity::{self, CoreId};
use crossbeam::thread;
use serde_json::{from_reader, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::Instant;
use transmission::{Client, ClientConfig};

pub fn load_json(file_path: String) -> Vec<String> {
    let file = fs::File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let torrent_files = json.get("torrents_files").expect("file should have time key").clone();
    // println!("\ntorrent_files {:?}", torrent_files);

    let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
    // println!("\ntorrents {:?}", torrents);
    torrents
}

pub fn merge_ts_ori(
    total_measured_pkt: usize,
    stop_ts_tcp: Vec<Instant>,
    stop_ts_non_tcp: HashMap<usize, Instant>,
) -> HashMap<usize, Instant> {
    let mut actual_ts = HashMap::<usize, Instant>::with_capacity(total_measured_pkt);
    let mut non_tcp_c = 0;

    for pivot in 1..total_measured_pkt + 1 {
        if stop_ts_non_tcp.contains_key(&pivot) {
            // non tcp ts
            let item = stop_ts_non_tcp.get(&pivot).unwrap();
            actual_ts.insert(pivot - 1, *item);
            // println!("INSERT: pivot: {:?} is {:?}", pivot - 1, *item);
            non_tcp_c += 1;
        } else {
            // tcp ts
            // println!(
            //     "INSERT: pivot: {:?} is {:?}",
            //     pivot - 1,
            //     stop_ts_tcp[pivot - non_tcp_c - 1]
            // );
            actual_ts.insert(pivot - 1, stop_ts_tcp[pivot - non_tcp_c - 1]);
        }
    }

    println!("merging finished!",);
    actual_ts
}

pub fn run_torrent_test(pivot: u64, workload: &mut Vec<String>, torrents_dir: &str, c: &Client) {
    // println!("run torrents {:?}", pivot);
    match workload.pop() {
        Some(torrent) => {
            println!("{:?} torrent is : {:?}", pivot, torrent);
            let torrent = torrents_dir.clone().to_owned() + &torrent;
            // println!("torrent dir is : {:?}", torrent_dir);
            let t = c.add_torrent_file(&torrent).unwrap();
            t.start();
        }
        None => {
            println!("no torrent");
        }
    }
}

pub fn task_scheduler(
    pivot: u64,
    c: &Client,
    workload: &mut Vec<String>,
    torrents_dir: &str,
    config_dir: &str,
    download_dir: &str,
) {
    // println!("run torrents {:?}", pivot);
    match workload.pop() {
        Some(torrent) => {
            println!("{:?} torrent is : {:?}", pivot, torrent);
            let torrent = torrents_dir.clone().to_owned() + &torrent;
            // println!("torrent dir is : {:?}", torrent_dir);
            run_torrent(c, &torrent, &config_dir.to_string(), &download_dir.to_string());
        }
        None => {
            println!("no torrent");
        }
    }
}

pub fn run_torrent(c: &Client, torrent: &str, config_dir: &str, download_dir: &str) {
    thread::scope(|s| {
        let core_ids = core_affinity::get_core_ids().unwrap();
        let handles = core_ids
            .into_iter()
            .map(|id| {
                s.spawn(move |_| {
                    // Pin this thread to a single CPU core.
                    core_affinity::set_for_current(id);
                    // Do more work after this.
                    //
                    if id.id == 5 as usize {
                        println!("Working in core {:?}", id);
                        let t = c.add_torrent_file(torrent).unwrap();
                        t.start();
                    }
                })
            })
            .collect::<Vec<_>>();

        for handle in handles.into_iter() {
            handle.join().unwrap();
        }
    })
    .unwrap();
}
