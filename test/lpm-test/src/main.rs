//! Longest Prefix Matching NF implemented in NetBricks.
//!
//! ## Description:
//! This is a longest prefix match (LPM) lookup table using the DIR-24-8 algorithm [16] in Rust,
//! and built a NetBricks NF that uses this data structure to route IP packets.
//!
//! For details please refer to the section 5.2.1 of the NetBricks paper.

#![feature(box_syntax)]
extern crate e2d2;
extern crate fnv;
extern crate rand;
extern crate time;

use self::nf::lpm;
use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PacketRx, PacketTx};
use e2d2::operators::{Batch, ReceiveBatch};
use e2d2::scheduler::{initialize_system, Scheduler, StandaloneScheduler};
use std::env;
use std::fmt::Display;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

mod nf;

const CONVERSION_FACTOR: f64 = 1000000000.;

fn test<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    println!("Test: Receiving started");
    //println!("Ports are {?}", ports);
    //dbg!(ports);
    for port in &ports {
        println!("Receiving port {}", port);
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| lpm(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

/// Parsing the configuration manually.
fn main() {
    let mut opts = basic_opts();
    opts.optflag("t", "test", "Test mode do not use real ports");

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let configuration = read_matches(&matches, &opts);
    let duration = configuration.duration;

    let phy_ports = !matches.opt_present("test");

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();

            if phy_ports {
                println!("Adding the pipeline b/c we just add that pipeline..");
                context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s)));
            } else {
                println!("Adding only a test pipeline..");
                context.add_test_pipeline(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s)));
            }
            context.execute();

            let mut pkts_so_far = (0, 0);
            let mut last_printed = 0.;
            const MAX_PRINT_INTERVAL: f64 = 30.;
            const PRINT_DELAY: f64 = 30.;
            let sleep_delay = (PRINT_DELAY / 2.) as u64;
            let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
            let sleep_time = Duration::from_millis(sleep_delay);
            println!("Init: 0 OVERALL RX 0.00 TX 0.00 CYCLE_PER_DELAY 0 0 0");
            let begining = Instant::now();

            loop {
                thread::sleep(sleep_time); // Sleep for a bit
                let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
                if now - start > PRINT_DELAY {
                    let mut rx = 0;
                    let mut tx = 0;
                    if phy_ports {
                        for port in context.ports.values() {
                            for q in 0..port.rxqs() {
                                let (rp, tp) = port.stats(q);
                                rx += rp;
                                tx += tp;
                            }
                        }
                    } else {
                        for port in context.virtual_ports.values() {
                            let (rp, tp) = port.stats();
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
                match duration {
                    Some(d) => {
                        let new_now = Instant::now();
                        if new_now.duration_since(begining) > Duration::new(d as u64, 0) {
                            println!("Have run for {:?}, system shutting down", d);
                            context.shutdown();
                            break;
                        }
                    }
                    None => {}
                }
            }
        }
        Err(ref e) => {
            println!("Error: {}", e);
            if let Some(backtrace) = e.backtrace() {
                println!("Backtrace: {:?}", backtrace);
            }
            process::exit(1);
        }
    }
}
