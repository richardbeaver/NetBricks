use self::utils::{load_torrent, read_torrent_file};
use downloader::Downloader;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::Browser;
use std::collections::HashMap;
use std::thread;
use std::time::Duration;
use storage::memory::MemoryStorage;
use storage::partial::PartialStorage;
use torrent::Torrent;
use transmission::{Client, ClientConfig};

use utils;

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

    // load_json("workload.json".to_string());
    //
    // load_torrent("test.torrent".to_string());
    // load_torrent("OpenBSD-6.6-amd64.iso.torrent".to_string());

    // let file_path = "alpine.torrent";
    let file_path = "OpenBSD-6.6-amd64.iso.torrent";
    let config_dir = "/";
    let download_dir = "/";

    let c = ClientConfig::new()
        .app_name("testing")
        .config_dir(config_dir)
        .download_dir(download_dir);
    let mut c = Client::new(c);

    let t = c.add_torrent_file(file_path).unwrap();
    t.start();

    // Run until done
    while t.stats().percent_complete < 1.0 {
        print!("{:#?}\r", t.stats().percent_complete);
    }
    c.close();

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
            // scheduling workload
            thread::sleep(sleep_time); // Sleep for a bit
            let now = time::precise_time_ns() as f64 / CONVERSION_FACTOR;
            if now - start > PRINT_DELAY {
                // println!("DEBUG: now is {:?}, start is {:?}", now, start);
                if now - last_printed > MAX_PRINT_INTERVAL {
                    println!("DEBUG: now - start is {:.2} ", now - start);
                    last_printed = now;
                    start = now;
                }
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
