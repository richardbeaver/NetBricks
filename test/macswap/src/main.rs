//! Mac addresses swap NF implemented in NetBricks.
//!
//! ## Description:
//! This NF swaps the source and destination ethernet address for received packets and forwards
//! them out the same port. The NetBricks NF adds no additional overhead when compared to a native
//! C NF.
//!
//! For details please refer to the section 5.3.1 of the NetBricks paper.

#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate rand;
extern crate time;

use self::nf::*;
use e2d2::config::{basic_opts, read_matches};
use e2d2::interface::{PacketRx, PacketTx};
use e2d2::operators::{Batch, ReceiveBatch};
use e2d2::scheduler::{initialize_system, Scheduler, StandaloneScheduler};
use std::env;
use std::fmt::Display;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod nf;

fn test<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    for port in &ports {
        println!("Receiving port {}", port);
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| macswap(ReceiveBatch::new(port.clone())).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}

fn main() {
    let mut opts = basic_opts();
    opts.optopt(
        "",
        "dur",
        "Test duration",
        "If this option is set to a nonzero value, then the \
         test will exit after X seconds.",
    );

    let args: Vec<String> = env::args().collect();
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    let mut configuration = read_matches(&matches, &opts);
    configuration.pool_size = 255;

    let test_duration: u64 = matches
        .opt_str("dur")
        .unwrap_or_else(|| String::from("0"))
        .parse()
        .expect("Could not parse test duration");
    println!("Duration is {}", test_duration);

    match initialize_system(&configuration) {
        Ok(mut context) => {
            context.start_schedulers();

            context.add_pipeline_to_run(Arc::new(move |p, s: &mut StandaloneScheduler| test(p, s)));
            context.execute();

            if test_duration != 0 {
                thread::sleep(Duration::from_secs(test_duration));
            } else {
                loop {
                    thread::sleep(Duration::from_secs(1));
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
