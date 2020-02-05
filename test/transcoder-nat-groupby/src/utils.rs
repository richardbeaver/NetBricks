use resize::Pixel::Gray8;
use resize::Type::Triangle;
use serde_json::{from_reader, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::time::{Duration, Instant};

// pub fn load_json(file_path: String) -> Vec<String> {
//     let file = fs::File::open(file_path).expect("file should open read only");
//     let json: Value = from_reader(file).expect("file should be proper JSON");
//
//     let torrent_files = json.get("torrents_files").expect("file should have time key").clone();
//     // println!("\ntorrent_files {:?}", torrent_files);
//
//     let torrents: Vec<String> = serde_json::from_value(torrent_files).unwrap();
//     // println!("\ntorrents {:?}", torrents);
//     torrents
// }

pub fn merge_ts_old(
    total_measured_pkt: usize,
    stop_ts_tcp: Vec<Instant>,
    stop_ts_non_tcp: HashMap<usize, Instant>,
) -> HashMap<usize, Instant> {
    let mut actual_ts = HashMap::<usize, Instant>::with_capacity(total_measured_pkt);
    let mut non_tcp_c = 0;

    for pivot in 1..total_measured_pkt + 1 {
        if stop_ts_non_tcp.contains_key(&pivot) {
            // non tcp ts
            let item = stop_ts_non_tcp.get(&pivot).unwrap();
            actual_ts.insert(pivot - 1, *item);
            // println!("INSERT: pivot: {:?} is {:?}", pivot - 1, *item);
            non_tcp_c += 1;
        } else {
            // tcp ts
            // println!(
            //     "INSERT: pivot: {:?} is {:?}",
            //     pivot - 1,
            //     stop_ts_tcp[pivot - non_tcp_c - 1]
            // );
            actual_ts.insert(pivot - 1, stop_ts_tcp[pivot - non_tcp_c - 1]);
        }
    }

    println!("merging finished!",);
    actual_ts
}

// pub fn async_run_torrents(workload: &mut Vec<String>, torrents_dir: &str, c: &Client) {
//     // println!("exec run torrents");
//     while let Some(torrent) = workload.pop() {
//         // println!("torrent is : {:?}", torrent);
//         let torrent = torrents_dir.clone().to_owned() + &torrent;
//         // println!("torrent dir is : {:?}", torrent_dir);
//         let t = c.add_torrent_file(&torrent).unwrap();
//         t.start();
//     }
// }
//
// pub fn run_torrents(workload: &mut Vec<String>, torrents_dir: &str, c: &Client) {
//     // println!("exec run torrents");
//     while let Some(torrent) = workload.pop() {
//         println!("torrent is : {:?}", torrent);
//         let torrent = torrents_dir.clone().to_owned() + &torrent;
//         // println!("torrent dir is : {:?}", torrent_dir);
//         let t = c.add_torrent_file(&torrent).unwrap();
//         t.start();
//     }
// }

pub fn run_transcode(pivot: u64) {
    let infile = "/home/jethros/dev/pvn-utils/data/tiny.y4m";
    // let outfile = "out.y4m";
    let width_height = "360x24";
    let outfile = "/home/jethros/dev/pvn-utils/data/output_videos/".to_owned() + &pivot.to_string() + ".y4m";
    for _ in 0..3 {
        transcode(infile.to_string(), outfile.to_string(), width_height.to_string());
    }
}

fn transcode(infile: String, outfile: String, width_height: String) {
    let mut infh: Box<dyn io::Read> = Box::new(File::open(&infile).unwrap());
    let mut outfh: Box<dyn io::Write> = Box::new(File::create(&outfile).unwrap());
    let dst_dims: Vec<_> = width_height.split("x").map(|s| s.parse().unwrap()).collect();

    let mut decoder = y4m::decode(&mut infh).unwrap();

    if decoder.get_bit_depth() != 8 {
        panic!(
            "Unsupported bit depth {}, this example only supports 8.",
            decoder.get_bit_depth()
        );
    }
    let (w1, h1) = (decoder.get_width(), decoder.get_height());
    let (w2, h2) = (dst_dims[0], dst_dims[1]);
    let mut resizer = resize::new(w1, h1, w2, h2, Gray8, Triangle);
    let mut dst = vec![0; w2 * h2];

    let mut encoder = y4m::encode(w2, h2, decoder.get_framerate())
        .with_colorspace(y4m::Colorspace::Cmono)
        .write_header(&mut outfh)
        .unwrap();

    loop {
        match decoder.read_frame() {
            Ok(frame) => {
                resizer.resize(frame.get_y_plane(), &mut dst);
                let out_frame = y4m::Frame::new([&dst, &[], &[]], None);
                if encoder.write_frame(&out_frame).is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
}
