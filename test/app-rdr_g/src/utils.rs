use failure::Fallible;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::vec::Vec;

/// Create the browser for RDR proxy (user browsing).
///
/// FIXME: Instead of using the particular forked branch we want to eventually use the official
/// headless chrome create but set those parameters correctly here.
pub fn browser_create() -> Fallible<Browser> {
    // /usr/bin/chromedriver
    // /usr/bin/chromium-browser

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

/// Simple user browse.
pub fn simple_user_browse(current_browser: &Browser, hostname: &String) -> Fallible<(bool, u128)> {
    let now = Instant::now();
    let current_tab = match current_browser.new_tab() {
        Ok(tab) => tab,
        Err(e) => {
            println!("RDR Tab failed: {:?}", hostname);
            println!("RDR Tab Error: {:?}", e);
            return Ok((false, now.elapsed().as_millis()));
        }
    };

    let http_hostname = "http://".to_string() + &hostname;

    current_tab.navigate_to(&http_hostname)?;

    Ok((true, now.elapsed().as_millis()))
}

/// RDR proxy browsing scheduler.
pub fn rdr_scheduler_ng(
    pivot: &usize,
    rdr_users: &Vec<i64>,
    current_work: Vec<(u64, String, i64)>,
    browser_list: &HashMap<i64, Browser>,
) -> Option<(usize, usize, usize, usize)> {
    let mut num_of_ok = 0;
    let mut num_of_err = 0;
    let mut num_of_visit = 0;
    let mut elapsed_time = Vec::new();

    for (milli, url, user) in current_work.into_iter() {
        println!("User {:?}: milli: {:?} url: {:?}", user, milli, url);

        if rdr_users.contains(&user) {
            match simple_user_browse(&browser_list[&user], &url) {
                Ok((val, t)) => {
                    if val {
                        num_of_ok += 1;
                        num_of_visit += 1;
                        elapsed_time.push(t as usize);
                    } else {
                        num_of_err += 1;
                        num_of_visit += 1;
                        elapsed_time.push(t as usize);
                    }
                }
                Err(e) => {
                    println!("DEBUG: this should not be reachable!!!");
                }
            }
        }
    }

    let total = elapsed_time.iter().sum();

    if num_of_visit > 0 {
        Some((num_of_ok, num_of_err, elapsed_time.len(), total))
    } else {
        None
    }
}
