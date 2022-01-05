use faktory::Job;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

/// Append job to a faktory queue.
pub fn append_job_faktory(pivot: u128, faktory_conn: Arc<Mutex<faktory::Producer<TcpStream>>>, _core_id: usize) {
    let infile = "/home/jethros/dev/pvn/utils/data/tiny.y4m";
    let width_height = "360x24";
    // let outfile = "/home/jethros/dev/pvn/utils/data/output_videos/".to_owned() + &pivot.to_string() + ".y4m";
    let outfile = "/data/output_videos/".to_owned() + &pivot.to_string() + ".y4m";

    faktory_conn
        .lock()
        .unwrap()
        .enqueue(Job::new(
            "app-xcdr_".to_owned() + 0.to_string(),
            vec![infile.to_string(), outfile, width_height.to_string()],
        ))
        .unwrap();
}
