#![feature(box_syntax)]
#![feature(asm)]
extern crate e2d2;
extern crate fnv;
extern crate getopts;
extern crate nix;
extern crate rand;
extern crate time;

use self::control::*;
use self::nf::*;
use e2d2::control::tcp::*;
use e2d2::interface::dpdk::*;
use e2d2::interface::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use getopts::Options;
use std::collections::HashMap;
use std::env;
use std::net::*;
use std::process;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
mod control;
mod nf;

const CONVERSION_FACTOR: f64 = 1000000000.;

fn recv_thread(ports: Vec<PortQueue>, core: i32, delay_arg: u64) {
    init_thread(core, core);
    println!("Receiving started");
    for port in &ports {
        println!(
            "Receiving port {} rxq {} txq {} on core {} delay {}",
            port.port.mac_address(),
            port.rxq(),
            port.txq(),
            core,
            delay_arg
        );
    }

    let pipelines: Vec<_> = ports
        .iter()
        .map(|port| delay(ReceiveBatch::new(port.clone()), delay_arg).send(port.clone()))
        .collect();
    println!("Running {} pipelines", pipelines.len());
    let mut sched = StandaloneScheduler::new();
    for pipeline in pipelines {
        sched.add_task(pipeline).unwrap();
    }
    let addr = SocketAddrV4::new(Ipv4Addr::from_str("0.0.0.0").unwrap(), 8001);
    let control = TcpControlServer::<ControlListener>::new(SocketAddr::V4(addr));
    sched.add_task(control).unwrap();
    sched.execute_loop();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("", "secondary", "run as a secondary process");
    opts.optopt("n", "name", "name to use for the current process", "name");
    opts.optmulti("p", "port", "Port to use", "[type:]id");
    opts.optmulti("c", "core", "Core to use", "core");
    opts.optopt("m", "master", "Master core", "master");
    opts.optopt("d", "delay", "Delay cycles", "cycles");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        print!("{}", opts.usage(&format!("Usage: {} [options]", program)));
        process::exit(0)
    }

    let delay_arg = matches
        .opt_str("d")
        .unwrap_or_else(|| String::from("100"))
        .parse()
        .expect("Could not parse delay");

    let cores_str = matches.opt_strs("c");
    let master_core = matches
        .opt_str("m")
        .unwrap_or_else(|| String::from("0"))
        .parse()
        .expect("Could not parse master core spec");
    println!("Using master core {}", master_core);
    let name = matches.opt_str("n").unwrap_or_else(|| String::from("recv"));

    let cores: Vec<i32> = cores_str
        .iter()
        .map(|n: &String| n.parse().ok().expect(&format!("Core cannot be parsed {}", n)))
        .collect();

    fn extract_cores_for_port(ports: &[String], cores: &[i32]) -> HashMap<String, Vec<i32>> {
        let mut cores_for_port = HashMap::<String, Vec<i32>>::new();
        for (port, core) in ports.iter().zip(cores.iter()) {
            cores_for_port.entry(port.clone()).or_insert(vec![]).push(*core)
        }
        cores_for_port
    }

    let primary = !matches.opt_present("secondary");

    let cores_for_port = extract_cores_for_port(&matches.opt_strs("p"), &cores);

    if primary {
        init_system_wl(&name, master_core, &[]);
    } else {
        init_system_secondary(&name, master_core);
    }

    let ports_to_activate: Vec<_> = cores_for_port.keys().collect();

    let mut queues_by_core = HashMap::<i32, Vec<_>>::with_capacity(cores.len());
    let mut ports = Vec::<Arc<PmdPort>>::with_capacity(ports_to_activate.len());
    for port in &ports_to_activate {
        let cores = cores_for_port.get(*port).unwrap();
        let queues = cores.len() as i32;
        let pmd_port =
            PmdPort::new_with_queues(*port, queues, queues, cores, cores).expect("Could not initialize port");
        for (idx, core) in cores.iter().enumerate() {
            let queue = idx as i32;
            queues_by_core
                .entry(*core)
                .or_insert(vec![])
                .push(PmdPort::new_queue_pair(&pmd_port, queue, queue).unwrap());
        }
        ports.push(pmd_port);
    }

    const _BATCH: usize = 1 << 10;
    const _CHANNEL_SIZE: usize = 256;
    let _thread: Vec<_> = queues_by_core
        .iter()
        .map(|(core, ports)| {
            let c = core.clone();
            let p: Vec<_> = ports.iter().map(|p| p.clone()).collect();
            std::thread::spawn(move || recv_thread(p, c, delay_arg))
        })
        .collect();
    let mut pkts_so_far = (0, 0);
    let mut last_printed = 0.;
    const MAX_PRINT_INTERVAL: f64 = 30.;
    const PRINT_DELAY: f64 = 15.;
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
            for port in &ports {
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
