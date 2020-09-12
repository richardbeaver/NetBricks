use faktory::{Job, Producer};
use std::fs::File;
use std::thread;
use std::time::Duration;

/// Append job to a faktory queue.
pub fn append_job_faktory(pivot: u128, faktory_conn: Option<&str>, expr_num: &str) {
    println!("Appending to Faktory ");
    let mut p = match Producer::connect(faktory_conn) {
        Ok(tcpstream) => tcpstream,
        Err(e) => {
            println!("Faktory connection failed {:?}", e);
            thread::sleep(Duration::from_millis(1));
            Producer::connect(faktory_conn).unwrap()
        }
    };

    let infile = "/home/jethros/dev/pvn/utils/data/tiny.y4m";
    let width_height = "360x24";
    let outfile = "/home/jethros/dev/pvn/utils/data/output_videos/".to_owned() + &pivot.to_string() + ".y4m";

    p.enqueue(Job::new(
        "app-xcdr_t-".to_owned() + expr_num,
        vec![infile.to_string(), outfile.to_string(), width_height.to_string()],
    ))
    .unwrap();
}
