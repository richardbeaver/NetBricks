use failure::Fallible;
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{Browser, Tab};
use rand::Rng;
use serde_json::{from_reader, Result, Value};
use std::collections::HashMap;
use std::fs::File;
use std::time::{Duration, Instant};
use std::vec::Vec;

/// Handy function to get the random number
fn get_magic_num(range: usize) -> usize {
    let num = rand::thread_rng().gen_range(0, range);
    num
}

/// Construct the workload from the session file.
///
/// https://kbknapp.github.io/doapi-rs/docs/serde/json/index.html
pub fn rdr_load_workload(
    file_path: String,
    num_of_secs: usize,
    num_of_user: usize,
) -> Result<HashMap<u64, HashMap<usize, Vec<(i32, String)>>>> {
    // time in second, workload in that second
    let mut workload = HashMap::<u64, HashMap<usize, Vec<(i32, String)>>>::with_capacity(num_of_secs);

    let file = File::open(file_path).expect("file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");

    for sec in 0..num_of_secs {
        // user, workload for that user
        let mut sec_wd = HashMap::<usize, Vec<(i32, String)>>::with_capacity(100);

        let urls_now = match json_data.get(sec.to_string()) {
            Some(val) => val.as_array(),
            None => continue,
        };
        let all_seq = match urls_now {
            Some(v) => v,
            None => continue,
        };

        for seq in all_seq {
            let visits = seq.as_array().unwrap();
            // println!("\n sec {:?}, break: {:?}", sec, visits);

            let mut vec_wd = Vec::new();
            for idx in 0..visits.len() {
                let time_url = visits[idx].as_str().unwrap().to_string();
                let v: Vec<&str> = time_url.split(':').collect();
                let wait_time: i32 = v[1].parse().unwrap();
                vec_wd.push((wait_time, v[0].to_string()));
            }
            let magic = get_magic_num(num_of_user);
            sec_wd.insert(magic, vec_wd);
        }
        workload.insert(sec as u64, sec_wd);
    }
    Ok(workload)
}

pub fn browser_create() -> Fallible<Browser> {
    // println!("try to create a browser",);
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.wait_for_initial_tab()?;
    tab.set_default_timeout(std::time::Duration::from_secs(100));

    // println!("Browser created",);
    Ok(browser)
}

pub fn user_browse(current_browser: &Browser, hostname: &String) -> Fallible<()> {
    // println!("Entering user browsing",);
    // Doesn't use incognito mode
    //
    let current_tab = current_browser.new_tab()?;

    // Incogeneto mode
    //
    // let incognito_cxt = current_browser.new_context()?;
    // let current_tab: Arc<Tab> = incognito_cxt.new_tab()?;

    let https_hostname = "https://".to_string() + &hostname;
    // let _ = current_tab.navigate_to(&https_hostname)?.wait_until_navigated()?;
    let _ = current_tab.navigate_to(&https_hostname)?;

    Ok(())
}

pub fn simple_scheduler(
    pivot: &u128,
    _num_of_users: &usize,
    current_work: HashMap<usize, String>,
    browser_list: &Vec<Browser>,
) {
    // println!("\npivot: {:?}", pivot);
    // println!("current work {:?}", current_work);

    for current_user in 1.._num_of_users + 1 {
        // for current_user in 1..10 {
        // println!("{:?}", current_work[&current_user]);
        // println!("current_user {:?}", current_user);
        match user_browse(&browser_list[current_user - 1], &current_work[&current_user]) {
            Ok(_) => {}
            Err(e) => println!("User {} caused an error: {:?}", current_user, e),
        }
    }
}

/// RDR proxy browsing scheduler.
///
///
// 4 [(4636, "fanfiction.net"), (9055, "bs.serving-sys.com")]
pub fn rdr_scheduler(
    pivot: &u64,
    _num_of_users: &usize,
    current_work: HashMap<usize, Vec<(i32, String)>>,
    browser_list: &Vec<Browser>,
) {
    let now = Instant::now();

    println!("\npivot: {:?}", pivot);
    // println!("current work {:?}", current_work);

    for (key, value) in current_work.into_iter() {
        println!("{:?} {:?}", key, value);
    }

    // for current_user in 1.._num_of_users + 1 {
    //     // for current_user in 1..10 {
    //     // println!("{:?}", current_work[&current_user]);
    //     // println!("current_user {:?}", current_user);
    //     match user_browse(&browser_list[current_user - 1], &current_work[&current_user]) {
    //         Ok(_) => {}
    //         Err(e) => println!("User {} caused an error: {:?}", current_user, e),
    //     }
    // }
}
