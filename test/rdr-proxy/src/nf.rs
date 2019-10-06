use self::utils::{extract_http_request, tab_create, tab_create_unwrap};
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
            //let tab = tab_create();

            let _tcph = p.get_header();

            tab_create_unwrap("lobste.rs".to_string());
            let _payload_size = p.payload_size();
            //println!("The packet header is {:?}", _tcph);

            //println!("payload is {:x?}", payload);

            if _payload_size > 3 {
                let payload = p.get_mut_payload();
                let host = extract_http_request(payload);
                match host {
                    Ok(h) => {
                        println!("hostname: {:?}", h);
                        tab_create(h);
                        tab_create("lobste.rs".to_string());
                        tab_create("www.usatoday.com".to_string());
                        // tab_create_unwrap(h);
                    }
                    Err(_) => {}
                }
                //extract_http_request(payload);
            }

            // let (buf, rest) = payload.split_at(16);
            // println!("http part is {:x?}", buf);
            //
            // let mut headers = [EMPTY_HEADER; 16];
            // let mut req = Request::new(&mut headers);
            //
            // println!("Parse request {:?}", req.parse(buf));
            //println!("is partial {:?}", req.parse(buf)?.is_partial());

            //
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
