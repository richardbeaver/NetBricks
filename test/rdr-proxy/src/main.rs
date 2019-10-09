//! A Remote Dependency Resolution (RDR) proxy network function will employ a headless browser and
//! fetch the top-level HTML based on the HTTP (or even HTTPS) request. The exact implementation is
//! in `nf.rs`.
#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate getopts;
extern crate rustls;
extern crate time;
extern crate webpki;
extern crate webpki_roots;
#[macro_use]
extern crate slog;
extern crate slog_scope;
extern crate slog_stdlog;
extern crate slog_term;
#[macro_use]
extern crate log;
extern crate base64;
extern crate failure;

extern crate bincode;
#[macro_use]
extern crate serde_derive;
extern crate serde;

extern crate headless_chrome;
extern crate rshttp;
extern crate tiny_http;

use self::nf::rdr_proxy;
use e2d2::allocators::CacheAligned;
use e2d2::config::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use slog::Drain;
use std::env;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod nf;
mod utils;

const ENABLE_LOGGING: bool = false;
const CONVERSION_FACTOR: f64 = 1_000_000_000.;

/// Test for the rdr proxy network function to schedule pipelines.
fn rdr_proxy_test<S: Scheduler + Sized>(ports: Vec<CacheAligned<PortQueue>>, sched: &mut S) {
    for port in &ports {
        println!(
            "Receiving port {} rxq {} txq {}",
            port.port.mac_address(),
            port.rxq(),
            port.txq()
        );
    }

    // create a pipeline for each port
    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| rdr_proxy(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();

    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

/// default main
fn main() {
    if ENABLE_LOGGING {
        //logging will incur severe perf overhead.
        let log_path = "rdr.log";
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(log_path)
            .unwrap();

        // create logger
        let decorator = slog_term::PlainSyncDecorator::new(file);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let logger = slog::Logger::root(drain, o!());

        // slog_stdlog uses the logger from slog_scope, so set a logger there
        let _guard = slog_scope::set_global_logger(logger);

        // register slog_stdlog as the log handler with the log crate
        slog_stdlog::init().unwrap();

        info!("Starting PVN RDR proxy network function");
    }

    // setup default parameters
    let opts = basic_opts();
    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);

    // configure and start the schedulers
    let mut config = initialize_system(&configuration).unwrap();
    config.start_schedulers();

    config.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| rdr_proxy_test(p, s)));
    config.execute();

    let mut pkts_so_far = (0, 0);
    let mut last_printed = 0.;
    const MAX_PRINT_INTERVAL: f64 = 60.;
    //const PRINT_DELAY: f64 = 15.;
    const PRINT_DELAY: f64 = 30.;
    let sleep_delay = (PRINT_DELAY / 2.) as u64;
    let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
    let sleep_time = Duration::from_millis(sleep_delay);
    println!("0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");

    loop {
        thread::sleep(sleep_time); // Sleep for a bit
        let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
        if now - start > PRINT_DELAY {
            let mut rx = 0;
            let mut tx = 0;
            for port in config.ports.values() {
                for q in 0..port.rxqs() {
                    let (rp, tp) = port.stats(q);
                    rx += rp;
                    tx += tp;
                }
            }
            let pkts = (rx, tx);
            let rx_pkts = pkts.0 - pkts_so_far.0;
            if rx_pkts > 0 || now - last_printed > MAX_PRINT_INTERVAL {
                println!(
                    "{:.2} OVERALL RX {:.2} TX {:.2}",
                    now - start,
                    rx_pkts as f64 / (now - start),
                    (pkts.1 - pkts_so_far.1) as f64 / (now - start)
                );
                last_printed = now;
                start = now;
                pkts_so_far = pkts;
            }
        }
    }
}
