use self::utils::{browser_create, extract_http_request, retrieve_bulk_pairs, tab_create};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use failure::Fallible;
use fnv::FnvHasher;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use headless_chrome::browser::tab::RequestInterceptionDecision;
use headless_chrome::protocol::network::methods::RequestPattern;
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{
    protocol::browser::{Bounds, WindowState},
    protocol::page::ScreenshotFormat,
    Browser, Tab,
};

use utils;

// type FnvHash = BuildHasherDefault<FnvHasher>;
// const BUFFER_SIZE: usize = 16384; // 2048, 4096, 8192, 16384

pub fn rdr_proxy<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // States that this NF needs to maintain.:parent
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // Browser list.
    let mut browser_list = HashMap::<Flow, Browser>::with_hasher(Default::default());
    // Temporary payload cache.
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());

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
            let flow = p.read_metadata();
            let _tcph = p.get_header();
            let _payload_size = p.payload_size();

            if _payload_size > 3 {
                let payload = p.get_payload();
                let host = extract_http_request(payload);
                trace!("New HTTP GET request, we have {:?} browsers now", browser_list.len());
                if browser_list.len() > 2 {
                    println!("{:?} browsers now", browser_list.len());
                }
                match host {
                    Ok(h) => {
                        info!("hostname: {:?}", h);

                        // FIXME: hack
                        //
                        // if browser_list.contains_key(flow) {
                        //     unimplemented!();
                        // // info!("browser list has this key:",);
                        // // let new_tab = tab_create().unwrap();
                        // // let used_tab = retrieve_bulk_pairs(h, new_tab).unwrap();
                        // //
                        // // browser_list.insert(*flow, used_tab);
                        // } else {
                        info!("browser list doesnot have the key: ",);
                        let new_browser = browser_create().unwrap();
                        info!("1",);
                        let used_browser = retrieve_bulk_pairs(h, new_browser, payload_cache);
                        match used_browser {
                            Ok(b) => {
                                info!("insert the browser ",);
                                browser_list.insert(*flow, b);
                            }
                            Err(e) => {
                                info!("Error is: {:?}", e);
                            }
                        }
                        // }
                    }
                    Err(_) => {}
                }
            }

            //
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
