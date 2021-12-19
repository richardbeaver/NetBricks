//! Utils functions for measuring the PVN NFs.
use crate::utils::Flow;
use serde_json::{from_reader, Value};
use statrs::statistics::{Max, Mean, Median, Min};
use statrs::statistics::{OrderStatistics, Variance};
use std::collections::HashMap;
use std::fs::File;
use std::time::Instant;

/// Epsilon.
pub const EPSILON: usize = 1000;
/// Number of packets to ignore before starting measurement. Currently deprecated.
pub const NUM_TO_IGNORE: usize = 0;

/// Estimated number of packets for allocating large size array for RDR NF.
pub const RDR_MEASURED_PKT: usize = 100_000_000;
/// Estimated number of packets for allocating large size array.
pub const TOTAL_MEASURED_PKT: usize = 200_000_000;

/// Time for the short experiment with instrumentation.
pub const SHORT_MEASURE_TIME: u64 = 181;
/// Time for the medium experiment with instrumentation.
pub const MEDIUM_MEASURE_TIME: u64 = 301;
/// Time for the long experiment with instrumentation.
pub const LONG_MEASURE_TIME: u64 = 601;
/// Time for the application experiment.
pub const APP_MEASURE_TIME: u64 = 610;

/// Fake flow when retrieving flow failed.
pub fn fake_flow() -> Flow {
    Flow {
        src_ip: 0_u32,
        dst_ip: 0_u32,
        src_port: 0_u16,
        dst_port: 0_u16,
        proto: 0_u8,
    }
}

/// experiment parameters.
#[derive(Debug, Clone, Copy)]
pub struct ExprParam {
    /// setup (workload level)
    pub setup: usize,
    /// TLSV setup
    pub tlsv_setup: usize,
    /// RDR setup
    pub rdr_setup: usize,
    /// XCDR setup
    pub xcdr_setup: usize,
    /// P2P setup
    pub p2p_setup: usize,
    /// iteration of this run
    pub iter: usize,
    /// whether we have turned on latency instrumentation
    pub inst: bool,
    /// running experiment time
    pub expr_time: u64,
}

/// Read various params from setup.
///
/// Currently returns: *setup* (which setup it is), *iter* (which iteration it
/// is), *inst* (instrumentation for retrieving latencies for every packet),
/// and *expr running time* (how long the NF will run).
///
/// This impl probably can be optimized.
pub fn read_setup_param(file_path: String) -> Option<ExprParam> {
    let file = File::open(file_path.clone()).expect("file should open read only");
    let read_json = file_path + "should be proper JSON";
    let json: Value = from_reader(file).expect(&read_json);

    let setup: Option<String> = match serde_json::from_value(json.get("setup").expect("file should have setup").clone())
    {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response for setup: {}", e);
            None
        }
    };
    let setup = setup.unwrap().parse::<usize>();

    // setup all NF setups
    let tlsv_setup: Option<String> =
        match serde_json::from_value(json.get("tlsv_setup").expect("file could have tlsv setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for tlsv_setup: {}", e);
                Some("0".to_string())
            }
        };
    let rdr_setup: Option<String> =
        match serde_json::from_value(json.get("rdr_setup").expect("file should have rdr_setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for rdr_setup: {}", e);
                Some("0".to_string())
            }
        };
    let xcdr_setup: Option<String> =
        match serde_json::from_value(json.get("xcdr_setup").expect("file should have xcdr_setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for xcdr_setup: {}", e);
                Some("0".to_string())
            }
        };
    let p2p_setup: Option<String> =
        match serde_json::from_value(json.get("p2p_setup").expect("file should have p2p_setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response for p2p_setup: {}", e);
                Some("0".to_string())
            }
        };
    let tlsv_setup = tlsv_setup.unwrap().parse::<usize>();
    let rdr_setup = rdr_setup.unwrap().parse::<usize>();
    let xcdr_setup = xcdr_setup.unwrap().parse::<usize>();
    let p2p_setup = p2p_setup.unwrap().parse::<usize>();

    let iter: Option<String> = match serde_json::from_value(json.get("iter").expect("file should have iter").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };
    let iter = iter.unwrap().parse::<usize>();

    let inst: Option<String> = match serde_json::from_value(json.get("inst").expect("file should have inst").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };
    let inst_val = match &*inst.unwrap() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    };

    let mode: Option<String> = match serde_json::from_value(json.get("mode").expect("file should have mode").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };
    let expr_time = match &*mode.unwrap() {
        "short" => Some(SHORT_MEASURE_TIME),
        "medium" => Some(MEDIUM_MEASURE_TIME),
        "long" => Some(LONG_MEASURE_TIME),
        _ => None,
    };

    if let (
        Ok(setup),
        Ok(tlsv_setup),
        Ok(rdr_setup),
        Ok(xcdr_setup),
        Ok(p2p_setup),
        Ok(iter),
        Some(inst),
        Some(expr_time),
    ) = (
        setup, tlsv_setup, rdr_setup, xcdr_setup, p2p_setup, iter, inst_val, expr_time,
    ) {
        Some(ExprParam {
            setup,
            tlsv_setup,
            rdr_setup,
            xcdr_setup,
            p2p_setup,
            iter,
            inst,
            expr_time,
        })
    } else {
        None
    }
}

/// Merge all the timestamps we have and generate meaningful latencies for each
/// packet.
///
/// The current implementation just works so please don't touch the code unless
/// you have time to verify the correctness.
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

/// Compute statistics for the latency results collected.
pub fn compute_stat(mut tmp_results: Vec<u128>) {
    tmp_results.sort_unstable();
    let mut results: Vec<f64> = tmp_results.into_iter().map(|item| item as f64).collect();
    let bar = results.percentile(99);
    let (rest, mut main): (_, Vec<_>) = results.into_iter().partition(|x| x >= &bar);
    println!("sorting and then type casting done",);

    println!("Details of the results in rest",);
    let rest_chunk_size = rest.len() / 100 + 1;
    //generate 100 groups
    for (rest_count, rest_chunk) in rest.chunks(rest_chunk_size).enumerate() {
        println!(
            "Rest_group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            rest_count,
            rest_chunk.median(),
            rest_chunk.mean(),
            rest_chunk.std_dev()
        );
    }

    println!("Details of the results in main",);
    let main_chunk_size = main.len() / 100 + 1;
    //generate 100 groups
    for (main_count, main_chunk) in main.chunks(main_chunk_size).enumerate() {
        println!(
            "Group {:?}, median: {:02?}, mean: {:02?}, std dev: {:02?}",
            main_count,
            main_chunk.median(),
            main_chunk.mean(),
            main_chunk.std_dev()
        );
    }

    let min = main.min();
    let max = main.max();
    println!(
        "Stat_extra, mean: {:?}, median: {:?}, std: {:?}, 90%iles: {:?}, 95%iles: {:?}, ",
        main.mean(),
        main.median(),
        main.std_dev(),
        main.percentile(90),
        main.percentile(95),
    );
    println!(
        "Stat, min: {:?}, 25%iles: {:?}, 50%iles: {:?}, 75%iles: {:?}, max: {:?}",
        min,
        main.percentile(25),
        main.percentile(50),
        main.percentile(75),
        max,
    );
}
