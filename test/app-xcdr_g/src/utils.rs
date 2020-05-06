use core_affinity::{self, CoreId};
use std::sync::{Arc, RwLock};
// use serde_json::{from_reader, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
// use std::thread;
// use std::time::{Duration, Instant};
use faktory::{Job, Producer};
use serde_json::{from_reader, Value};

/// Read setup for transcoder NF only.
///
/// We need to get the port number for faktory queue besides the setup value.
pub fn xcdr_read_setup(file_path: String) -> Option<(usize, String)> {
    let file = File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let setup: Option<usize> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let port: Option<usize> = match serde_json::from_value(json.get("port").expect("file should have port").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    if port.is_some() || setup.is_some() {
        return Some((setup.unwrap(), port.unwrap().to_string()));
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
/// 2500 videos per second -- 50% pktgen sending rate
/// 5000 videos per second -- 100% pktgen sending rate
pub fn xcdr_retrieve_param(setup_val: usize) -> Option<(usize, usize)> {
    let mut map = HashMap::new();
    map.insert(1, (50, 1));
    map.insert(2, (100, 1));
    map.insert(3, (500, 1));
    map.insert(4, (1000, 1));
    map.insert(5, (1000, 2)); // 2
    map.insert(6, (1000, 5));

    map.remove(&setup_val)
}

// Append job to local queue. (deprecated)
pub fn append_job(pivot: u128, job_queue: &Arc<RwLock<Vec<(String, String, String)>>>) {
    // println!("enter append with pivot: {}", pivot);
    let infile = "/home/jethros/dev/pvn-utils/data/tiny.y4m";
    // let outfile = "out.y4m";
    let width_height = "360x24";
    for i in 0..1 {
        let outfile = "/home/jethros/dev/pvn-utils/data/output_videos/".to_owned()
            + &pivot.to_string()
            + "_"
            + &i.to_string()
            + ".y4m";

        let mut w = job_queue.write().unwrap();
        w.push((infile.to_string(), outfile.to_string(), width_height.to_string()));
        // println!(
        //     "appending: {:?} {:?} {:?}",
        //     infile.to_string(),
        //     outfile.to_string(),
        //     width_height.to_string()
        // );
    }
}

// Append job to a faktory queue.
pub fn append_job_faktory(pivot: u128, num_of_vid: usize, faktory_conn: Option<&str>) {
    // println!("enter append with pivot: {}", pivot);
    let infile = "/home/jethros/dev/pvn-utils/data/tiny.y4m";
    // let outfile = "out.y4m";
    let width_height = "360x24";
    for i in 0..num_of_vid {
        let outfile = "/home/jethros/dev/pvn-utils/data/output_videos/".to_owned()
            + &pivot.to_string()
            + "_"
            + &i.to_string()
            + ".y4m";

        let mut p = Producer::connect(faktory_conn).unwrap();
        p.enqueue(Job::new(
            "app-xcdr_t",
            vec![infile.to_string(), outfile.to_string(), width_height.to_string()],
        ))
        .unwrap();
        println!(
            "appending: {:?} {:?} {:?}",
            infile.to_string(),
            outfile.to_string(),
            width_height.to_string()
        );
    }
}
