/// Hard code page size.
///
/// This is different from hugepage/TLB.
use statrs::statistics::OrderStatistics;
use statrs::statistics::Variance;
use statrs::statistics::{Max, Mean, Median, Min};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::vec;

pub const EPSILON: usize = 1000;
pub const NUM_TO_IGNORE: usize = 0;
pub const TOTAL_MEASURED_PKT: usize = 300_000_000;
pub const MEASURE_TIME: u64 = 60;

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

pub fn compute_stat(mut tmp_results: Vec<u128>) {
    tmp_results.sort();
    let mut results: Vec<f64> = tmp_results.into_iter().map(|item| item as f64).collect();
    // let results = vec::map(tmp_results, |&e| e as f64);
    // let results = tmp_results.map(|&e| e as f64);
    println!("sorting and then type casting done",);

    //generate 100 groups
    for chunk in results.chunks(100) {
        println!("mean: {:02?}, std dev: {:02?}", chunk.mean(), chunk.std_dev());
    }

    let min = results.min();
    let max = results.max();
    println!(
        "min: {:?}, max: {:?}, mean: {:?}, median: {:?}",
        min,
        max,
        results.mean(),
        results.median(),
    );
    println!("std: {:?}", results.std_dev());
    println!(
        "75%iles: {:?}, 90%iles: {:?}, 95%iles: {:?}",
        results.percentile(75),
        results.percentile(90),
        results.percentile(95),
    );
}
