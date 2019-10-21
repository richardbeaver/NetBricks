use e2d2::utils::Flow;
use failure::Fallible;
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

pub fn load_json(file_path: String) -> Vec<String> {
    let file = File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let torrent_files = json.get("torrents_files").expect("file should have time key").clone();
    // println!("\ntorrent_files {:?}", torrent_files);

    let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
    // println!("\ntorrents {:?}", torrents);
    torrents
}
