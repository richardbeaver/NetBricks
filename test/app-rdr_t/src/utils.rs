use crate::prune_workload::curate_broken_records;
use failure::Error;
use failure::Fallible;
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{Browser, Tab};
use rand::Rng;
use serde_json::{from_reader, Result, Value};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use std::vec::Vec;

/// Construct the workload from the session file.
///
/// https://kbknapp.github.io/doapi-rs/docs/serde/json/index.html

pub fn rdr_load_workload(
    file_path: String,
    num_of_secs: usize,
    num_of_user: usize,
) -> Result<HashMap<usize, Vec<(u64, String, usize)>>> {
    // time in second, workload in that second
    // let mut workload = HashMap::<usize, HashMap<usize, Vec<(u64, String)>>>::with_capacity(num_of_secs);
    let mut workload = HashMap::<usize, Vec<(u64, String, usize)>>::with_capacity(num_of_secs);

    let file = File::open(file_path).expect("file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");
    // println!("{:?}", json_data);

    for sec in 0..num_of_secs {
        // println!("sec {:?}", sec,);
        // user, workload for that user
        //
        // sec = 266
        // sec_wd = {'86': [39, 'thumb.brandreachsys.com'], '23': [42, 'facebook.com'], '84': [86, 'ynetnews.com'], '33': [284, 'techbargains.com'], '9': [309, 'bing.com'], '76': [357, 'eventful.com'], '43': [365, 'ad.yieldmanager.com'], '63': [468, 'ads.brazzers.com'], '72': [520, 'sidereel.com'], '57': [586, 'daum.net'], '81': [701, 'target.com'], '95': [732, 'lezhin.com'], '88': [802, 'nba.com'], '49': [827, 'web4.c2.cyworld.com'], '27': [888, 'hv3.webstat.com'], '98': [917, 'youtube.com']}
        // let mut sec_wd = HashMap::<usize, Vec<(u64, String)>>::with_capacity(100);
        // we keep track of the millisecond appeared
        let mut millis: Vec<(u64, String, usize)> = Vec::new();

        // println!("{:?} {:?}", sec, json_data.get(sec.to_string()));
        let urls_now = match json_data.get(sec.to_string()) {
            Some(val) => val,
            None => continue,
        };
        // println!("{:?}", urls_now);
        for user in 0..num_of_user {
            let urls = match urls_now.get(user.to_string()) {
                Some(val) => val.as_array(),
                None => continue,
            };
            // println!("{:?}", urls.unwrap());

            let mut broken_urls = curate_broken_records();

            if broken_urls.contains(urls.unwrap()[1].as_str().unwrap()) {
                continue;
            } else {
                millis.push((
                    urls.unwrap()[0].as_u64().unwrap(),
                    urls.unwrap()[1].as_str().unwrap().to_string(),
                    user,
                ));
            }
        }
        millis.sort();

        workload.insert(sec, millis);
    }
    Ok(workload)
}

// /usr/bin/chromedriver
// /usr/bin/chromium-browser
pub fn browser_create() -> Fallible<Browser> {
    let timeout = Duration::new(1000, 0);

    let options = LaunchOptionsBuilder::default()
        .headless(true)
        .idle_browser_timeout(timeout)
        .build()
        .expect("Couldn't find appropriate Chrome binary.");
    let browser = Browser::new(options)?;
    // let tab = browser.wait_for_initial_tab()?;
    // tab.set_default_timeout(std::time::Duration::from_secs(100));

    // println!("Browser created",);
    Ok(browser)
}

pub fn user_browse(current_browser: &Browser, hostname: &String) -> Fallible<()> {
    let now = Instant::now();

    let tab = current_browser.new_tab()?;

    let http_hostname = "http://".to_string() + &hostname;
    println!("{:?}", http_hostname);

    tab.navigate_to(&http_hostname)?;
    match tab.wait_for_element("html") {
        Ok(_) => println!("Visit {:?}: got html", http_hostname),
        Err(e) => println!("Broswing failed: {:?}", e),
    }

    Ok(())
}

/// RDR proxy browsing scheduler.
// 4 [(4636, "fanfiction.net"), (9055, "bs.serving-sys.com")]
pub fn rdr_scheduler(
    now: Instant,
    pivot: &usize,
    num_of_ok: &mut usize,
    num_of_err: &mut usize,
    elapsed_time: &mut Vec<u128>,
    _num_of_users: &usize,
    current_work: Vec<(u64, String, usize)>,
    browser_list: &Vec<Browser>,
) {
    for (milli, url, user) in current_work.into_iter() {
        if milli >= 750 {
            break;
        }
        println!("User {:?}: milli: {:?} url: {:?}", user, milli, url);

        if now.elapsed().as_millis() < milli as u128 {
            let one_millis = Duration::from_millis(1);
            std::thread::sleep(one_millis);
        } else {
            match user_browse(&browser_list[user], &url) {
                Ok(_) => {}
                Err(e) => {
                    println!("User {} caused an error", user,);
                }
            }
        }
    }
}

/// RDR proxy browsing scheduler.
// 4 [(4636, "fanfiction.net"), (9055, "bs.serving-sys.com")]
pub fn rdr_scheduler_ng(pivot: &usize, current_work: Vec<(u64, String, usize)>, browser_list: &Vec<Browser>) {
    for (milli, url, user) in current_work.into_iter() {
        println!("User {:?}: milli: {:?} url: {:?}", user, milli, url);

        match user_browse(&browser_list[user], &url) {
            Ok(_) => {}
            Err(e) => {
                println!("User {} caused an error", user,);
            }
        }
    }
}

pub fn rdr_retrieve_users(setup_val: usize) -> Option<usize> {
    let mut map = HashMap::new();
    map.insert(1, 2);
    map.insert(2, 4);
    map.insert(3, 8);
    map.insert(4, 12);
    map.insert(5, 16);
    map.insert(6, 20);

    // map.insert(1, 1);
    // map.insert(2, 2);
    // map.insert(3, 4);
    // map.insert(4, 6);
    // map.insert(5, 8);
    // map.insert(6, 10);

    map.remove(&setup_val)
}
