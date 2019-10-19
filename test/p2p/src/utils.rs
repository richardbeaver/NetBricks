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

    // create_workload(time, total_visited_times, urls, visited_times)
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

    // println!("splitting");
    // split_to_files("./test.out", torrent);
}
