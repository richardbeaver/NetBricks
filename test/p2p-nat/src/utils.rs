use serde_json::{from_reader, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::time::{Duration, Instant};

pub fn load_json(file_path: String) -> Vec<String> {
    let file = fs::File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let torrent_files = json.get("torrents_files").expect("file should have time key").clone();
    // println!("\ntorrent_files {:?}", torrent_files);

    let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
    // println!("\ntorrents {:?}", torrents);
    torrents
}

pub fn merge_ts(
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
