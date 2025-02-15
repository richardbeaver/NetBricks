//! Utils functions for the PVN Transcoder NF.
use serde_json::{from_reader, Value};
use std::collections::HashMap;
use std::fs::File;

/// Time for the short experiment with instrumentation.
pub const SHORT_MEASURE_TIME: u64 = 181;
/// Time for the medium experiment with instrumentation.
pub const MEDIUM_MEASURE_TIME: u64 = 301;
/// Time for the long experiment with instrumentation.
pub const LONG_MEASURE_TIME: u64 = 601;
/// Time for the application experiment.
pub const APP_MEASURE_TIME: u64 = 610;

/// experiment parameters.
#[derive(Debug, Clone, Copy)]
pub struct XcdrExprParam {
    /// setup (workload level)
    pub setup: usize,
    /// setup (workload level)
    pub xcdr_setup: usize,
    /// iteration of this run
    pub iter: usize,
    /// whether we have turned on latency instrumentation
    pub inst: bool,
    /// running experiment time
    pub expr_time: u64,
}

/// Read setup for transcoder NF. This function returns <setup, expr number, inst, measure time>.
pub fn xcdr_read_setup(file_path: String) -> Option<XcdrExprParam> {
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
    let xcdr_setup: Option<String> =
        match serde_json::from_value(json.get("xcdr_setup").expect("file should have xcdr_setup").clone()) {
            Ok(val) => Some(val),
            Err(e) => {
                println!("Malformed JSON response: {}", e);
                None
            }
        };
    let setup = setup.unwrap().parse::<usize>();
    let xcdr_setup = xcdr_setup.unwrap().parse::<usize>();

    let iter: Option<String> = match serde_json::from_value(json.get("iter").expect("file should have setup").clone()) {
        Ok(val) => Some(val),
        Err(e) => {
            println!("Malformed JSON response: {}", e);
            None
        }
    };
    let iter = iter.unwrap().parse::<usize>();

    let inst: Option<String> = match serde_json::from_value(json.get("inst").expect("file should have setup").clone()) {
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

    let mode: Option<String> = match serde_json::from_value(json.get("mode").expect("file should have setup").clone()) {
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

    if let (Ok(setup), Ok(xcdr_setup), Ok(iter), Some(inst), Some(expr_time)) =
        (setup, xcdr_setup, iter, inst_val, expr_time)
    {
        Some(XcdrExprParam {
            setup,
            xcdr_setup,
            iter,
            inst,
            expr_time,
        })
    } else {
        None
    }
}

/// Return the time span between submitting jobs to the faktory job queue
/// based on the setup value for running transcoder experiments.
///
/// We configure the number of users per setup: 10, 50, 100, 200, 500, 1000. We
/// calculate the time duration between submitted jobs as follows:
///     jobs_submitted_per_second = (number_of_users * 1.13MB/second) / video_unit [10MB]
///     duration = 1 second [1000 milliseconds] / jobs_submitted_per_second
pub fn xcdr_retrieve_param(setup_val: usize) -> Option<u128> {
    let mut map = HashMap::new();
    map.insert(1, 1); // 10
    map.insert(2, 6); // 50
    map.insert(3, 11); // 100
    map.insert(4, 23); // 200
    map.insert(5, 57); // 500
    map.insert(6, 113); // 1000

    // hack for task scheduling
    map.insert(7, 23); // 200
    map.insert(8, 45); // 400
    map.insert(9, 68); // 600
    map.insert(10, 90); // 800
    map.insert(11, 113); // 1000
    map.insert(12, 136); // 1200
    map.insert(13, 158); // 1400
    map.insert(14, 181); // 1600
    map.insert(15, 203); // 1800
    map.insert(16, 226); // 2000

    let time_span = 1_000 / map.remove(&setup_val).unwrap();
    println!(
        "setup: {:?} maps to time span: {:?} millisecond",
        setup_val, time_span as u128
    );

    Some(time_span as u128)
}
