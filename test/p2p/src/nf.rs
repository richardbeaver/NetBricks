use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use job_scheduler::{Job, JobScheduler};
use rand::Rng;
use std::thread;
use std::time::Duration;
use transmission::{Client, ClientConfig};
use utils::load_json;

pub fn p2p<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    // big-buck-bunny.torrent  cosmos-laundromat.torrent  sintel.torrent  tears-of-steel.torrent  wired-cd.torrent

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
        .transform(box move |_| {
            // transmission setup

            let config_dir = "/data/config";
            let download_dir = "/data/downloads";
            let torrents_dir = "/data/torrents/";

            // let config_dir = "config";
            // let download_dir = "downloads";
            // let torrents_dir = "torrent_files/";

            let config = ClientConfig::new()
                .app_name("testing")
                .config_dir(config_dir)
                .use_utp(false)
                .download_dir(download_dir);
            let c = Client::new(config);

            let workload = load_json("workload.json".to_string());
            // let workload = load_json("small_workload.json".to_string());
            // println!("\nall the torrents are : {:?}", workload);
            let mut iterator = workload.iter();

            let mut sched = JobScheduler::new();

            sched.add(Job::new("1/1 * * * * *".parse().unwrap(), move || {
                let delay = rand::thread_rng().gen_range(0, 10);
                thread::sleep(std::time::Duration::new(delay, 0));
                println!("I get executed with the delay of {:?} seconds!", delay);

                let t = iterator.next();
                match t {
                    Some(torrent) => {
                        println!("torrent is : {:?}", torrent);
                        let torrent = torrents_dir.to_owned() + torrent;
                        // println!("torrent dir is : {:?}", torrent_dir);
                        let t = c.add_torrent_file(&torrent).unwrap();
                        t.start();
                    }
                    None => {
                        println!("Nothing in the work queue, waiting for 30 seconds");
                        thread::sleep(std::time::Duration::new(30, 0));
                    }
                }
            }));

            loop {
                sched.tick();

                std::thread::sleep(Duration::from_millis(500));
            }

            // Run until done
            // while t.stats().percent_complete < 1.0 {
            //     print!("{:#?}\r", t.stats().percent_complete);
            //     print!("{:#?}\r", t2.stats().percent_complete);
            // }
            // c.close();
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
