use core_affinity::{self, CoreId};
use faktory::{Job, Producer};
use serde_json::{from_reader, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::sync::{Arc, RwLock};

/// Read setup for transcoder NF only.
///
/// We need to get the port number for faktory queue besides the setup value.
pub fn xcdr_read_setup(file_path: String) -> Option<(usize, String, String)> {
    let file = File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let setup: Option<String> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let port: Option<String> = match serde_json::from_value(json.get("port").expect("file should have port").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let expr_num: Option<String> =
        match serde_json::from_value(json.get("expr_num").expect("file should have expr_num").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response: {}", e);
                None
            }
        };

    if port.is_some() || setup.is_some() || expr_num.is_some() {
        return Some((
            setup.unwrap().parse::<usize>().unwrap(),
            port.unwrap().to_string(),
            expr_num.unwrap().to_string(),
        ));
    } else {
        println!("Setup: {:?} and Port: {:?} have None values", setup, port);
        return None;
    }
}

/// Get the parameters for running transcoder experiments.
///
/// 50 videos per second -- 1% pktgen sending rate
/// 100 videos per second -- 2% pktgen sending rate
/// 500 videos per second -- 10% pktgen sending rate
/// 1000 videos per second -- 20% pktgen sending rate
/// 2000 videos per second -- 40% pktgen sending rate
/// 5000 videos per second -- 100% pktgen sending rate
pub fn xcdr_retrieve_param(setup_val: usize) -> Option<usize> {
    let mut map = HashMap::new();
    map.insert(1, 50);
    map.insert(2, 100);
    map.insert(3, 500);
    map.insert(4, 1000);
    map.insert(5, 2500);
    map.insert(6, 5000);

    map.remove(&setup_val)
}

/// Append job to a faktory queue.
pub fn append_job_faktory(pivot: u64, num_of_vid: usize, faktory_conn: Option<&str>, expr_num: &str) {
    let mut p = match Producer::connect(faktory_conn) {
        Ok(tcpstream) => tcpstream,
        Err(e) => {
            println!("{:?}", e);
            Producer::connect(faktory_conn).unwrap()
        }
    };

    let infile = "/home/jethros/dev/pvn/utils/data/tiny.y4m";
    let width_height = "360x24";
    for i in 0..num_of_vid {
        let outfile = "/home/jethros/dev/pvn/utils/data/output_videos/".to_owned()
            + &pivot.to_string()
            + "_"
            + &i.to_string()
            + ".y4m";

        p.enqueue(Job::new(
            "app-xcdr_t-".to_owned() + expr_num,
            vec![infile.to_string(), outfile.to_string(), width_height.to_string()],
        ))
        .unwrap();
    }
}
