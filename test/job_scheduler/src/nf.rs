// use self::utils::{load_torrent, read_torrent_file};
// use chrono::prelude::*;
// use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::Browser;
use job_scheduler::{Job, JobScheduler};
use rand::Rng;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use transmission::{Client, ClientConfig};

// use utils;

const CONVERSION_FACTOR: f64 = 1_000_000_000.;

pub fn p2p<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Browser list.
    let mut browser_list = HashMap::<Flow, Browser>::with_hasher(Default::default());
    // Temporary payload cache.
    let mut request_cache = HashMap::<Flow, Vec<Request>>::with_hasher(Default::default());
    let mut responses_cache = HashMap::<
        Flow,
        Vec<(
            events::ResponseReceivedEventParams,
            methods::GetResponseBodyReturnObject,
        )>,
    >::with_hasher(Default::default());

    // Time states for scheduling tasks
    const MAX_PRINT_INTERVAL: f64 = 10.;
    const PRINT_DELAY: f64 = 10.;
    let sleep_delay = (PRINT_DELAY / 2.) as u64;
    let mut start = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
    let sleep_time = Duration::from_millis(sleep_delay);
    let mut last_printed = 0.;

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            // FIXME: what is this?!
            // p.get_mut_header().swap_addresses();
            p.get_mut_header();
        })
        .parse::<IpHeader>()
        .group_by(
            2,
            box move |p| if p.get_header().protocol() == 6 { 0 } else { 1 },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
        .parse::<TcpHeader>()
        .transform(box move |p| {
            let mut sched = JobScheduler::new();
            let mut rng = rand::thread_rng();

            sched.add(Job::new("1/10 * * * * *".parse().unwrap(), || {
                let delay = rand::thread_rng().gen_range(0, 10);
                thread::sleep(std::time::Duration::new(delay, 0));
                println!("I get executed with the delay of {:?} seconds!", delay);
            }));

            loop {
                sched.tick();

                std::thread::sleep(Duration::from_millis(500));
            }

            // // scheduling workload
            // thread::sleep(sleep_time); // Sleep for a bit
            // let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
            // if now - start > PRINT_DELAY {
            //     // println!("DEBUG: now is {:?}, start is {:?}", now, start);
            //     if now - last_printed > MAX_PRINT_INTERVAL {
            //         println!("DEBUG: now - start is {:.2} ", now - start);
            //         sched.tick();
            //         last_printed = now;
            //         start = now;
            //     }
            // }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
