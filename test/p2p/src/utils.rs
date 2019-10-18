use downloader::Downloader;
use e2d2::utils::Flow;
use failure::Fallible;
use headless_chrome::browser::tab::RequestInterceptionDecision;
use headless_chrome::protocol::network::methods::RequestPattern;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{Browser, Tab};
use rand::{distributions::Uniform, Rng}; // 0.6.5
use rshttp::{HttpHeaderName, HttpRequest};
use rustc_serialize::json::Json;
use serde_json::{from_reader, from_value, Value};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;
use storage::memory::MemoryStorage;
use storage::partial::PartialStorage;
use torrent::Torrent;

use bencode;
use torrent;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct HttpRequestNotExtractedError;

#[derive(Debug, Clone)]
pub struct RequestResponsePair {
    request: Request,
    response_params: events::ResponseReceivedEventParams,
    response_body: methods::GetResponseBodyReturnObject,
}

pub fn extract_http_request(payload: &[u8]) -> Result<String, HttpRequestNotExtractedError> {
    // if the first three bytes are "GET" or "POS", there's a chance the packet is HTTP
    // if the first three bytes are 0x16, 0x30, 0x00-0x03, there's a chance the packet is TLS

    let get: &[u8] = &[71, 69, 84]; // GET
    let post: &[u8] = &[80, 79, 83]; // POS
    let http: &[u8] = &[72, 84, 84]; // HTT
    let tls0: &[u8] = &[22, 3, 0];
    let tls1: &[u8] = &[22, 3, 1];
    let tls2: &[u8] = &[22, 3, 2];
    let tls3: &[u8] = &[22, 3, 3];

    let (head, _) = payload.split_at(3);

    if head == get {
        let payload_str = match std::str::from_utf8(payload) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(HttpRequestNotExtractedError),
        };

        let get_request = HttpRequest::new(&payload_str).unwrap();
        let headers = get_request.headers;

        let mut _iterator = headers.iter();

        while let Some(h) = _iterator.next() {
            if h.name == HttpHeaderName::Host {
                // println!("\nImportant: issuing a HTTP request for {:?}", h.value);
                return Ok(h.value.clone());
            } else {
                continue;
            }
        }
        return Err(HttpRequestNotExtractedError);
    } else {
        Err(HttpRequestNotExtractedError)
    }
}

#[allow(dead_code)]
pub fn pkt_workload() {
    // let flow = p.read_metadata();
    // let _tcph = p.get_header();
    // let _payload_size = p.payload_size();
    //
    // if _payload_size > 3 {
    //     let payload = p.get_payload();
    //     let host = extract_http_request(payload);
    //     trace!("New HTTP GET request, we have {:?} browsers now", browser_list.len());
    //     if browser_list.len() > 2 {
    //         // println!("{:?} browsers now", browser_list.len());
    //     }
    //     match host {
    //         Ok(h) => {
    //             info!("hostname: {:?}", h);
    //
    //             // FIXME: hack
    //             //
    //             // if browser_list.contains_key(flow) {
    //             //     unimplemented!();
    //             // // info!("browser list has this key:",);
    //             // // let new_tab = tab_create().unwrap();
    //             // // let used_tab = retrieve_bulk_pairs(h, new_tab).unwrap();
    //             // //
    //             // // browser_list.insert(*flow, used_tab);
    //             // } else {
    //             info!("browser list doesnot have the key: ",);
    //             let new_browser = browser_create().unwrap();
    //             info!("1",);
    //             let result_pair = retrieve_bulk_pairs(h, new_browser);
    //             match result_pair {
    //                 Ok((used_browser, current_request, current_responses)) => {
    //                     // Ok((used_browser, request_response_pair)) => {
    //                     // payload_cache.insert(*flow, request_response_pair);
    //
    //                     browser_list.insert(*flow, used_browser);
    //                     request_cache.insert(*flow, current_request);
    //                     responses_cache.insert(*flow, current_responses);
    //
    //                     // match used_browser {
    //                     //     Ok(b) => {
    //                     //         info!("insert the browser ",);
    //                     //     }
    //                     //     Err(e) => {
    //                     //         info!("Error is: {:?}", e);
    //                     //     }
    //                     // }
    //                 }
    //                 Err(e) => info!("Error is: {:?}", e),
    //             }
    //         }
    //         Err(_) => {}
    //     }
    // }
}

pub fn browser_create() -> Fallible<Browser> {
    // println!("try to create a browser",);
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.wait_for_initial_tab()?;

    println!("Browser created",);
    Ok(browser)
}

#[allow(dead_code)]
pub fn tab_create() -> Fallible<Arc<Tab>> {
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.new_tab()?;

    // ONLY TEST
    let http_hostname = "http://lobste.rs".to_string();
    let data = tab.navigate_to(&http_hostname).unwrap().wait_until_navigated().unwrap();

    Ok(tab)
}

pub fn retrieve_bulk_pairs(
    hostname: String,
    current_browser: Browser,
) -> Fallible<(
    Browser,
    Vec<Request>,
    Vec<(
        events::ResponseReceivedEventParams,
        methods::GetResponseBodyReturnObject,
    )>,
)> {
    // Doesn't use incognito mode
    //
    let current_tab = current_browser.new_tab()?;

    // Incogeneto mode
    //
    // let incognito_cxt = current_browser.new_context()?;
    // let current_tab: Arc<Tab> = incognito_cxt.new_tab()?;

    // println!("try to retrieve bulk",);

    let patterns = vec![
        RequestPattern {
            url_pattern: None,
            resource_type: None,
            interception_stage: Some("HeadersReceived"),
        },
        RequestPattern {
            url_pattern: None,
            resource_type: None,
            interception_stage: Some("Request"),
        },
    ];

    let request = Arc::new(Mutex::new(Vec::new()));
    let request2 = request.clone();

    current_tab.enable_request_interception(
        &patterns,
        Box::new(move |transport, session_id, intercepted| {
            request2.lock().unwrap().push(intercepted.request);

            RequestInterceptionDecision::Continue
        }),
    )?;

    let final_request: Vec<_> = request.lock().unwrap().clone();

    // println!("bulk1",);
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responses2 = responses.clone();

    current_tab.enable_response_handling(Box::new(move |response, fetch_body| {
        // NOTE: you can only fetch the body after it's been downloaded, which might be some time
        // after the initial 'response' (with status code, headers, etc.) has come back. hence this
        // sleep:
        sleep(Duration::from_millis(50));

        let body = fetch_body().unwrap();

        responses2.lock().unwrap().push((response, body));
    }))?;

    let final_responses: Vec<_> = responses.lock().unwrap().clone();

    // println!("responses {:?}", responses);
    // println!("RDR tab enable response",);

    // This is a hack
    if hostname == "wikia.com" {
        // let hostname = "lobste.rs";
        let hostname = "tmz.com";

        // println!("Changed wikia to lobsters",);
        // println!("\nDEBUG: Hostname: {:?}", hostname);
        let http_hostname = "http://".to_string() + &hostname;
        // println!("Break",);

        let data = current_tab.navigate_to(&http_hostname)?.wait_until_navigated()?;

        // let request_response_pair = RequestResponsePair {
        //     request: request,
        //     response_params: response_params,
        //     response_body: response_body,
        // };

        // println!("OK",);
        return Ok((current_browser, final_request, final_responses));
    }

    // println!("\nDEBUG: Hostname: {:?}", hostname);
    // println!("Break",);

    let http_hostname = "http://".to_string() + &hostname;
    let data = current_tab.navigate_to(&http_hostname)?.wait_until_navigated()?;

    // let request_response_pair = RequestResponsePair {
    //     request: request,
    //     response_params: response_params,
    //     response_body: response_body,
    // };

    // println!("retrieve: OK",);
    Ok((current_browser, final_request, final_responses))
}

pub fn load_json(file_path: String) {
    let file = File::open("workload.json").expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let time_value = json.get("time").expect("file should have time key").clone();
    let user_num_value = json
        .get("number_of_user")
        .expect("file should have number_of_user key")
        .clone();
    let total_visited_times_value = json
        .get("total_visited_times")
        .expect("file should have time key")
        .clone();
    let urls_value = json.get("urls").expect("file should have number_of_user key").clone();
    let visited_times_value = json
        .get("visited_times")
        .expect("file should have number_of_user key")
        .clone();

    let time: usize = serde_json::from_value(time_value).unwrap();
    println!("time: {}", time);
    let user_num: usize = serde_json::from_value(user_num_value).unwrap();
    println!("user_num: {}", user_num);
    let total_visited_times: usize = serde_json::from_value(total_visited_times_value).unwrap();
    println!("total visited time: {}", time);
    let urls: Vec<String> = serde_json::from_value(urls_value).unwrap();
    println!("urls: {:?}", urls);
    let visited_times: Vec<u64> = serde_json::from_value(visited_times_value).unwrap();
    println!("visited_times: {:?}", visited_times);

    create_workload(time, total_visited_times, urls, visited_times)
}

fn create_workload(time: usize, total_visited_times: usize, urls: Vec<String>, visited_times: Vec<u64>) {
    let bucket_size = time * 6;
    let mut workload: Vec<Vec<String>> = Vec::new();

    let mut rng = rand::thread_rng();
    let range = Uniform::new(0, bucket_size as u64);

    let index_list: Vec<u64> = (0..total_visited_times).map(|_| rng.sample(&range)).collect();
    let mut iter = index_list.iter();

    // for n in 0..=urls.len() {
    //     for i in 0..=visited_times[n].len() {
    //         workload[iter.next().unwrap()].push(urls[n]);
    //     }
    //     println!("{}", n);
    // }

    unimplemented!();
}

pub fn read_torrent_file<P: AsRef<Path>>(path: P) -> Option<(Torrent, [u8; 20])> {
    let mut file = File::open(path).expect("failed to open file");
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).expect("failed to read file");

    let bvalue = match bencode::decode(&contents) {
        Ok(x) => x,
        Err(e) => {
            println!("failed to parse file:\n  {:?}", e);
            return None;
        }
    };

    let (torrent, info_hash) = match torrent::from_bvalue(bvalue) {
        Ok(x) => x,
        Err(e) => {
            println!("failed to parse file:\n  {:?}", e);
            return None;
        }
    };

    Some((torrent, info_hash))
}

pub fn split_to_files<P: AsRef<Path>>(source: P, torrent: Torrent) {
    let mut source = File::open(source).expect("failed to open source file");
    use std::io::prelude::*;
    let mut data = Vec::new();
    source.read_to_end(&mut data).expect("failed to read source");
    let mut start = 0_usize;
    for file in torrent.info.files.into_iter() {
        let mut dest = File::create(file.path.clone()).expect("failed to create file");
        let end = start + file.length as usize;
        println!("interval {} - {} goes to {:?}", start, end, file.path.clone());
        dest.write_all(&data[start..end]).expect("failed to write");
        start = end;
    }
    println!("wrote total {} bytes", start);
}

pub fn load_torrent(file_path: String) {
    println!("Starting p2p downloading",);

    // ????
    // let args: Vec<String> = env::args().collect();
    // let path = match args.into_iter().nth(1) {
    //     Some(arg) => {
    //         println!("{:?}", arg);
    //         arg
    //     }
    //     None => {
    //         println!("Usage: thing <torrent file>");
    //         return;
    //     }
    // };

    println!("Torrent file: {}", file_path);

    let (torrent, info_hash) = read_torrent_file(file_path.clone()).unwrap();

    println!("Parsed file!");
    println!("Downloading: {:?}", torrent.info.root);

    let mut downloader: Downloader<PartialStorage<MemoryStorage>> = Downloader::new(info_hash, torrent.clone());

    downloader.run();

    println!("splitting");
    split_to_files("./test.out", torrent);
}
