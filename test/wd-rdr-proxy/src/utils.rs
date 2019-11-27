use failure::Fallible;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::Browser;
use headless_chrome::LaunchOptionsBuilder;
use serde_json::{from_reader, Value};
use std::collections::HashMap;
use std::fs::File;
use std::vec::Vec;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct HttpRequestNotExtractedError;

#[derive(Debug, Clone)]
pub struct RequestResponsePair {
    request: Request,
    response_params: events::ResponseReceivedEventParams,
    response_body: methods::GetResponseBodyReturnObject,
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

pub fn load_json(
    file_path: String,
    _num_of_users: usize,
    num_of_secs: usize,
) -> Result<Vec<HashMap<usize, String>>, HttpRequestNotExtractedError> {
    let file = File::open(file_path).expect("file should open read only");
    let json: Value = from_reader(file).expect("file should be proper JSON");

    let mut workload: Vec<HashMap<usize, String>> = Vec::new();

    for mut current_time in 0..num_of_secs {
        current_time += 1;
        let mut current_map: HashMap<usize, String> = HashMap::new();
        // println!("current time is {:?}", current_time);
        // println!("last thing before panic",);

        // Get all browsing records for that second
        let all = json.get(current_time.to_string());
        let all_users = match all {
            Some(a) => a.clone(),
            None => continue,
        };
        // println!("DEBUG: all {:?}", all_users);

        // Get the browsing url for all users
        for i in 1..201 {
            // println!("DEBUG: i is {:?}", i);
            let cur_user = all_users.get(i.to_string());
            let c = match cur_user {
                Some(current_url) => current_url.clone(),
                None => continue,
            };

            let cur_url: String = serde_json::from_value(c).unwrap();
            current_map.insert(i, cur_url);
        }
        // println!("map of the time {:?} is {:?}\n", current_time, current_map);
        workload.push(current_map);
    }

    // println!("\nthe whole workload is {:?}", workload);

    // println!("\nFinish\n",);
    Ok(workload)
}

pub fn user_browse(current_browser: &Browser, hostname: String) -> Fallible<()> {
    // println!("Entering user browsing",);
    // Doesn't use incognito mode
    //
    let current_tab = current_browser.new_tab()?;

    // Incogeneto mode
    //
    // let incognito_cxt = current_browser.new_context()?;
    // let current_tab: Arc<Tab> = incognito_cxt.new_tab()?;

    let https_hostname = "https://".to_string() + &hostname;
    let _ = current_tab.navigate_to(&https_hostname)?.wait_until_navigated()?;

    Ok(())
}
