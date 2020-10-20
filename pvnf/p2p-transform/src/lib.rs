//! NAT Network Funcion implemented in NetBricks.
//!
//! ## Description:
//! This NF is based on MazuNAT [41] a Click based NAT implemented by Mazu Networks, and commonly
//! used in academic research.
//!
//! For details please refer to the section 5.2.2 of the NetBricks paper.

#![feature(box_syntax)]
extern crate core_affinity;
extern crate crossbeam;
extern crate e2d2;
extern crate fnv;
extern crate fork;
extern crate getopts;
extern crate rand;
extern crate serde_json;
extern crate time;
extern crate transmission_rpc;

use self::nf::p2p;
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
mod utils;

const CONVERSION_FACTOR: f64 = 1000000000.;

pub fn p2p_test<T, S>(ports: Vec<T>, sched: &mut S)
where
    T: PacketRx + PacketTx + Display + Clone + 'static,
    S: Scheduler + Sized,
{
    println!("Receiving started");

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| p2p(ReceiveBatch::new(port.clone()), sched).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());

    // schedule pipelines
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
}
