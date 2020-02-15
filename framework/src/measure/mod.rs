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
    println!("sorting and then type casting done",);

    let mut count = 0;
    let chunk_size = results.len() / 100;
    //generate 100 groups
    for chunk in results.chunks(chunk_size) {
        println!(
            "Group {:?}, mean: {:02?}, std dev: {:02?}",
            count,
            chunk.mean(),
            chunk.std_dev()
        );
        count += 1;
    }

    let min = results.min();
    let max = results.max();
    println!(
        "Stat, min: {:?}, max: {:?}, mean: {:?}, median: {:?}, std: {:?}",
        min,
        max,
        results.mean(),
        results.median(),
        results.std_dev(),
    );
    println!(
        "Stat, 75%iles: {:?}, 90%iles: {:?}, 95%iles: {:?}",
        results.percentile(75),
        results.percentile(90),
        results.percentile(95),
    );
}
