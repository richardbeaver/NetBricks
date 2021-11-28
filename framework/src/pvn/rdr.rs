//! Utils functions for the PVN RDR NF.
use crate::pvn::unresolvable::curate_unresolvable_records;
use serde_json::{from_reader, Value, json};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Error, ErrorKind, Result};
use std::vec::Vec;

/// setup profile and user data dir with different disk setup
pub fn rdr_read_user_data_dir(file_path: String) -> Result<String> {
    let file = File::open(file_path.clone()).expect("file should open read only");
    let read_json = file_path + "should be proper JSON";
    let json: Value = from_reader(file).expect(&read_json);

    let disk_type = match json.get("disk") {
        Some(val) => Some(val),
        None => {
            println!("disk setup should exist but not, using hdd by default..");
            Some(json!("hdd"))
        }
    };
    match disk_type {
        // --profile-directory="C:\temp\profile" --user-data-dir="C:\temp\profile\userdata"
        Some(val) => {
            if val == "hdd" {
                println!("running chrome with hdd");
                Ok("/data/tmp/profile".to_string())
            } else {
                println!("running chrome with ssd");
                Ok("/home/jethros/data/profile".to_string())
            }
        }
        None => {
            println!("unable to read disk setup");
            Err(Error::new(ErrorKind::Other, "unable to read disk setup"))
        }
    }
}

/// Construct the workload from the session file.
///
/// https://kbknapp.github.io/doapi-rs/docs/serde/json/index.html
pub fn rdr_load_workload(
    file_path: String,
    num_of_secs: usize,
    rdr_users: Vec<i64>,
) -> serde_json::Result<HashMap<usize, Vec<(u64, String, i64)>>> {
    // time in second, workload in that second
    let mut workload = HashMap::<usize, Vec<(u64, String, i64)>>::with_capacity(rdr_users.len());

    let file = File::open(file_path).expect("file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");

    for sec in 0..num_of_secs {
        let mut millis: Vec<(u64, String, i64)> = Vec::new();

        let urls_now = match json_data.get(sec.to_string()) {
            Some(val) => val,
            None => continue,
        };
        for user in &rdr_users {
            let urls = match urls_now.get(user.to_string()) {
                Some(val) => val.as_array(),
                None => continue,
            };

            let broken_urls = curate_unresolvable_records();

            if broken_urls.contains(urls.unwrap()[1].as_str().unwrap()) {
                continue;
            } else {
                millis.push((
                    urls.unwrap()[0].as_u64().unwrap(),
                    urls.unwrap()[1].as_str().unwrap().to_string(),
                    *user as i64,
                ));
            }
        }
        millis.sort();

        workload.insert(sec, millis);
    }
    Ok(workload)
}

/// Retrieve the number of users based on our setup configuration.
pub fn rdr_retrieve_users(rdr_setup: usize) -> Option<usize> {
    let mut map = HashMap::new();
    map.insert(1, 5);
    map.insert(2, 10);
    map.insert(3, 20);
    map.insert(4, 40);
    map.insert(5, 80);
    map.insert(6, 100);

    map.remove(&rdr_setup)
}

/// Read the pregenerated randomness seed from file.
pub fn rdr_read_rand_seed(num_of_users: usize, iter: usize) -> Result<Vec<i64>> {
    let rand_seed_file = "/home/jethros/dev/pvn/utils/rand_number/rand.json";
    let mut rand_vec = Vec::new();
    let file = File::open(rand_seed_file).expect("rand seed file should open read only");
    let json_data: Value = from_reader(file).expect("file should be proper JSON");

    match json_data.get("rdr") {
        Some(rdr_data) => match rdr_data.get(&num_of_users.clone().to_string()) {
            Some(setup_data) => match setup_data.get(iter.to_string()) {
                Some(data) => {
                    for x in data.as_array().unwrap() {
                        rand_vec.push(x.as_i64().unwrap());
                        // println!("RDR user: {:?}", x.as_i64().unwrap());
                    }
                }
                None => println!("No rand data for iter {:?} for users {:?}", iter, num_of_users),
            },
            None => println!("No rand data for users {:?}", num_of_users),
        },
        None => println!("No rdr data in the rand seed file"),
    }
    println!(
        "Fetch rand seed for num_of_users: {:?}, iter: {:?}.\nrdr users: {:?}",
        num_of_users, iter, rand_vec
    );
    Ok(rand_vec)
}
