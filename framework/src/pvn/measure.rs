use serde_json::{from_reader, Value};
use statrs::statistics::OrderStatistics;
use statrs::statistics::Variance;
use statrs::statistics::{Max, Mean, Median, Min};
use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::time::Instant;

pub const EPSILON: usize = 1000;
pub const NUM_TO_IGNORE: usize = 0;
pub const TOTAL_MEASURED_PKT: usize = 300_000_000;
pub const MEASURE_TIME: u64 = 60;
pub const APP_MEASURE_TIME: u64 = 610;

/// Read setup for NF only.
// FIXME: this might be improved as we can read multiple params together etc
pub fn read_setup_iter(file_path: String) -> Option<(String, String)> {
    let file = File::open(file_path.clone()).expect("file should open read only");
    let read_json = file_path + "should be proper JSON";
    let json: Value = from_reader(file).expect(&read_json);

    let setup: Option<String> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    let iter: Option<String> = match serde_json::from_value(json.get("iter").expect("file should have setup").clone()) {
        Ok(val) => {
            println!("response: {}", val);
            Some(val)
        }
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };

    if setup.is_some() && iter.is_some() {
        Some((setup.unwrap(), iter.unwrap()))
    } else {
        None
    }
}

pub fn merge_ts(
    total_measured_pkt: usize,
    stop_ts_matched: Vec<Instant>,
    stop_ts_not_matched: HashMap<usize, Instant>,
) -> HashMap<usize, Instant> {
    let mut actual_ts = HashMap::<usize, Instant>::with_capacity(total_measured_pkt);
    let mut not_matched_c = 0;

    for pivot in 1..total_measured_pkt + 1 {
        if stop_ts_not_matched.contains_key(&pivot) {
            // non tcp ts
            let item = stop_ts_not_matched.get(&pivot).unwrap();
            actual_ts.insert(pivot - 1, *item);
            // println!("INSERT: pivot: {:?} is {:?}", pivot - 1, *item);
            not_matched_c += 1;
        } else {
            // NOTE: we need this early stop because of the drifting behavior in groupby operations
            if pivot - not_matched_c - 1 == stop_ts_matched.len() {
                println!("merging finished!",);
                return actual_ts;
            }
            actual_ts.insert(pivot - 1, stop_ts_matched[pivot - not_matched_c - 1]);
        }
    }

    println!("This should never be reached!",);
    actual_ts
}

pub fn compute_stat(mut tmp_results: Vec<u128>) {
    tmp_results.sort();
    let mut results: Vec<f64> = tmp_results.into_iter().map(|item| item as f64).collect();
    let bar = results.percentile(99);
    let (rest, mut results): (_, Vec<_>) = results.into_iter().partition(|x| x >= &bar);
    println!("sorting and then type casting done",);

    println!("Details of the results in rest",);
    let mut count1 = 0;
    let chunk_size1 = rest.len() / 100 + 1;
    //generate 100 groups
    for chunk in rest.chunks(chunk_size1) {
        println!(
            "Rest_group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            count1,
            chunk.median(),
            chunk.mean(),
            chunk.std_dev()
        );
        count1 += 1;
    }

    println!("Details of the results in main",);
    let mut count = 0;
    let chunk_size = results.len() / 100 + 1;
    //generate 100 groups
    for chunk in results.chunks(chunk_size) {
        println!(
            "Group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            count,
            chunk.median(),
            chunk.mean(),
            chunk.std_dev()
        );
        count += 1;
    }

    let min = results.min();
    let max = results.max();
    println!(
        "Stat_extra, mean: {:?}, median: {:?}, std: {:?}, 90%iles: {:?}, 95%iles: {:?}, ",
        results.mean(),
        results.median(),
        results.std_dev(),
        results.percentile(90),
        results.percentile(95),
    );
    println!(
        "Stat, min: {:?}, 25%iles: {:?}, 50%iles: {:?}, 75%iles: {:?}, max: {:?}",
        min,
        results.percentile(25),
        results.percentile(50),
        results.percentile(75),
        max,
    );
}
