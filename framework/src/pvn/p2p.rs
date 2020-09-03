use serde_json::{from_reader, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::Result;

/// Get the parameters for running p2p experiments.
///
/// 1 torrent job in total -- 3% pktgen sending rate
/// 5 torrent job in total -- 13% pktgen sending rate
/// 10 torrent job in total -- 25% pktgen sending rate
/// 20 torrent job in total -- 50% pktgen sending rate
/// 30 torrent job in total -- 75% pktgen sending rate
/// 40 torrent job in total -- 100% pktgen sending rate
pub fn p2p_retrieve_param(setup_val: usize) -> Option<usize> {
    let mut map = HashMap::new();
    map.insert(2, 1);
    map.insert(1, 10);
    map.insert(3, 50);
    map.insert(4, 100);
    map.insert(5, 150);
    map.insert(6, 200);

    map.insert(11, 1);
    map.insert(12, 1);
    map.insert(13, 1);
    map.insert(14, 1);
    map.insert(15, 1);
    map.insert(16, 1);
    map.insert(17, 1);
    map.insert(18, 1);
    map.insert(19, 1);
    map.insert(20, 1);

    map.remove(&setup_val)
}

///
pub fn p2p_fetch_workload(fp_setup: String) -> Option<&'static str> {
    let mut map: HashMap<usize, &str> = HashMap::new();

    // load setup param
    let file = File::open(fp_setup.clone()).expect("file should open read only");
    let read_json = fp_setup + "should be proper JSON";
    let json_data: Value = from_reader(file).expect(&read_json);

    let setup: Option<String> =
        match serde_json::from_value(json_data.get("setup").expect("file should have setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for setup: {}", e);
                None
            }
        };
    let setup_val = setup.unwrap().parse::<usize>().unwrap();

    let p2p_type: Option<String> =
        match serde_json::from_value(json_data.get("p2p_type").expect("file should have setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for p2p_type: {}", e);
                None
            }
        };

    match p2p_type.clone().unwrap().as_ref() {
        "p2p_ext" => {
            println!("Got p2p_ext");
            map.insert(11, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-1.json");
            map.insert(12, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-2.json");
            map.insert(13, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-3.json");
            map.insert(14, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-4.json");
            map.insert(15, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-5.json");
            map.insert(16, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-6.json");
            map.insert(17, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-7.json");
            map.insert(18, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-8.json");
            map.insert(19, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-9.json");
            map.insert(20, "/home/jethros/dev/pvn/utils/workloads/p2p-single-workload-10.json");
        }
        "p2p_controlled" => {
            println!("Got p2p_controlled");
            map.insert(1, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
            map.insert(2, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
            map.insert(3, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
            map.insert(4, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
            map.insert(5, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
            map.insert(6, "/home/jethros/dev/pvn/utils/workloads/p2p_controlled_workload.json");
        }
        "p2p_general" => {
            println!("Got p2p_general");
            map.insert(1, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
            map.insert(2, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
            map.insert(3, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
            map.insert(4, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
            map.insert(5, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
            map.insert(6, "/home/jethros/dev/pvn/utils/workloads/p2p-workload.json");
        }
        &_ => println!("Unknown p2p type: {:?}", p2p_type.unwrap()),
    }

    map.remove(&setup_val)
}

/// Load json workload for P2P.
pub fn load_json(fp_workload: String, p2p_torrents: Vec<i64>) -> Vec<String> {
    let file = File::open(fp_workload).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let torrent_files = json.get("torrents_files").expect("file should have time key").clone();

    let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
    torrents
}

/// Read random seed from rand_seed file.
pub fn p2p_read_rand_seed(num_of_torrents: usize, iter: String) -> Result<Vec<i64>> {
    println!("num_of_torrents: {:?}, iter: {:?}", num_of_torrents, iter);
    let rand_seed_file = "/home/jethros/dev/pvn/utils/rand_number/rand.json";
    let mut rand_vec = Vec::new();
    let file = File::open(rand_seed_file).expect("rand seed file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");

    match json_data.get("p2p") {
        Some(p2p_data) => match p2p_data.get(&num_of_torrents.clone().to_string()) {
            Some(setup_data) => match setup_data.get(iter.clone().to_string()) {
                Some(data) => {
                    for x in data.as_array().unwrap() {
                        rand_vec.push(x.as_i64().unwrap());
                        println!("P2P torrent: {:?}", x.as_i64().unwrap());
                    }
                }
                None => println!("No rand data for iter {:?} for torrent {:?}", iter, num_of_torrents),
            },
            None => println!("No rand data for torrents {:?}", num_of_torrents),
        },
        None => println!("No p2p data in the rand seed file"),
    }
    Ok(rand_vec)
}
