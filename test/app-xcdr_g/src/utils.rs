use core_affinity::{self, CoreId};
use crossbeam::thread;
use resize::Pixel::Gray8;
use resize::Type::Triangle;
use std::fs::File;
use std::io;
use std::time::{Duration, Instant};

pub fn run_transcode_crossbeam(pivot: u128) {
    thread::scope(|s| {
        let core_ids = core_affinity::get_core_ids().unwrap();
        let handles = core_ids
            .into_iter()
            .map(|id| {
                s.spawn(move |_| {
                    core_affinity::set_for_current(id);

                    if id.id == 5 as usize {
                        println!("Working in core {:?}", id);
                        let infile = "/home/jethros/dev/pvn-utils/data/tiny.y4m";
                        // let outfile = "out.y4m";
                        let width_height = "360x24";
                        for i in 0..10 {
                            let outfile = "/home/jethros/dev/pvn-utils/data/output_videos/".to_owned()
                                + &pivot.to_string()
                                + "_"
                                + &i.to_string()
                                + ".y4m";
                            transcode(infile.to_string(), outfile.to_string(), width_height.to_string());
                        }
                    }
                })
            })
            .collect::<Vec<_>>();

        for handle in handles.into_iter() {
            handle.join().unwrap();
        }
    })
    .unwrap();
}

pub fn run_transcode_native(pivot: u128) {
    let core_ids = core_affinity::get_core_ids().unwrap();

    let handles = core_ids
        .into_iter()
        .map(|id| {
            std::thread::spawn(move || {
                core_affinity::set_for_current(id);

                if id.id == 5 as usize {
                    println!("Working in core {:?}", id);
                    let infile = "/home/jethros/dev/pvn-utils/data/tiny.y4m";
                    // let outfile = "out.y4m";
                    let width_height = "360x24";
                    for i in 0..10 {
                        let outfile = "/home/jethros/dev/pvn-utils/data/output_videos/".to_owned()
                            + &pivot.to_string()
                            + "_"
                            + &i.to_string()
                            + ".y4m";
                        transcode(infile.to_string(), outfile.to_string(), width_height.to_string());
                    }
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles.into_iter() {
        handle.join().unwrap();
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
