use self::utils::{browser_create, extract_http_request, retrieve_bulk_pairs, RequestResponsePair};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::Browser;
use std::collections::HashMap;

use utils;

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
    let mut request_cache = HashMap::<Flow, Vec<Request>>::with_hasher(Default::default());
    let mut responses_cache = HashMap::<
        Flow,
        Vec<(
            events::ResponseReceivedEventParams,
            methods::GetResponseBodyReturnObject,
        )>,
    >::with_hasher(Default::default());

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
                // println!("New HTTP GET request, we have {:?} browsers now", browser_list.len());
                if browser_list.len() > 5 {
                    println!("{:?} browsers now", browser_list.len());
                }
                match host {
                    Ok(h) => {
                        // println!("hostname: {:?}", h);

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
                        // println!("browser list doesnot have the key: ",);
                        let new_browser = browser_create().unwrap();
                        // println!("1",);
                        let result_pair = retrieve_bulk_pairs(h, new_browser);

                        match result_pair {
                            Ok((used_browser, current_request, current_responses)) => {
                                // Ok((used_browser, request_response_pair)) => {
                                // payload_cache.insert(*flow, request_response_pair);

                                browser_list.insert(*flow, used_browser);
                                request_cache.insert(*flow, current_request);
                                responses_cache.insert(*flow, current_responses);

                                // match used_browser {
                                //     Ok(b) => {
                                //         info!("insert the browser ",);
                                //     }
                                //     Err(e) => {
                                //         info!("Error is: {:?}", e);
                                //     }
                                // }
                            }
                            Err(e) => println!("Error is: {:?}", e),
                        }
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
