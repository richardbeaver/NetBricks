use self::utils::{browser_create, load_json, user_browse};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use headless_chrome::Browser;
use job_scheduler::{Job, JobScheduler};
use std::thread;
use std::time::Duration;

use utils;

pub fn rdr_proxy<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    // States that this NF needs to maintain.
    //
    // The RDR proxy network function needs to maintain a list of active headless browsers. This is
    // for the purpose of simulating multi-container extension in Firefox and multiple users. We
    // also need to maintain a content cache for the bulk HTTP request and response pairs.

    let workload_path = "workloads/current_workload.json";
    let num_of_users = 140;
    let num_of_secs = 2000;

    // let workload_path = "workloads/simple_workload.json";
    // let num_of_users = 20;
    // let num_of_secs = 100;

    // Browser list.
    let mut browser_list: Vec<Browser> = Vec::new();

    let workload = load_json(workload_path.to_string(), num_of_users, num_of_secs).unwrap();

    for _ in 0..num_of_users {
        let browser = browser_create().unwrap();
        browser_list.push(browser);
    }
    println!("All browsers are created ",);

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
            let mut sched = JobScheduler::new();
            let mut iterator = workload.iter();
            let mut count = 0;

            sched.add(Job::new("1/1 * * * * *".parse().unwrap(), || {
                let t = iterator.next();
                count += 1;
                // println!("count: {:?}", count);
                match t {
                    Some(current_work) => {
                        // println!("current work {:?}", current_work);
                        for current_user in 1..num_of_users + 1 {
                            // println!("{:?}", current_work[&current_user]);
                            // println!("current_user {:?}", current_user);
                            match user_browse(&browser_list[current_user - 1], current_work[&current_user].clone()) {
                                Ok(_) => {}
                                Err(e) => println!("Error is {:?}", e),
                            }
                            // user_browse(&browser_list[current_user], current_work[&current_user].clone());
                        }
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
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
