extern crate base64;
extern crate tiny_http;

use failure::Fallible;
use std::fs;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread::sleep;
use std::time::Duration;

use headless_chrome::browser::tab::RequestInterceptionDecision;
use headless_chrome::protocol::network::methods::RequestPattern;
use headless_chrome::protocol::network::Cookie;
use headless_chrome::protocol::runtime::methods::{RemoteObjectSubtype, RemoteObjectType};
use headless_chrome::protocol::RemoteError;
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{
    protocol::browser::{Bounds, WindowState},
    protocol::page::ScreenshotFormat,
    Browser, Tab,
};

fn main() -> Fallible<()> {
    // Create a headless browser, navigate to wikipedia.org, wait for the page
    // to render completely, take a screenshot of the entire page
    // in JPEG-format using 75% quality.
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");
    let browser = Browser::new(options)?;
    let tab = browser.wait_for_initial_tab()?;

    let patterns = vec![
        RequestPattern {
            url_pattern: None,
            resource_type: None,
            interception_stage: Some("HeadersReceived"),
        },
        RequestPattern {
            url_pattern: None,
            resource_type: None,
            interception_stage: Some("Request"),
        },
    ];

    tab.enable_request_interception(
        &patterns,
        Box::new(|transport, session_id, intercepted| {
            println!("\nDEBUG: url content: {:?}", intercepted.request.url);
            println!("\nDEBUG: {:?}", intercepted.request);
            if intercepted.request.url.ends_with(".js") {
                println!("DEBUG: jackpot! We have JS code",);
                let js_body = r#"document.body.appendChild(document.createElement("hr"));"#;
                let js_response = tiny_http::Response::new(
                    200.into(),
                    vec![tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/javascript"[..]).unwrap()],
                    js_body.as_bytes(),
                    Some(js_body.len()),
                    None,
                );

                let mut wrapped_writer = Vec::new();
                js_response
                    .raw_print(&mut wrapped_writer, (1, 2).into(), &[], false, None)
                    .unwrap();

                let base64_response = base64::encode(&wrapped_writer);

                RequestInterceptionDecision::Response(base64_response)
            } else {
                RequestInterceptionDecision::Continue
            }
        }),
    )?;

    let responses = Arc::new(Mutex::new(Vec::new()));
    // let responses2 = responses.clone();

    tab.enable_response_handling(Box::new(move |response, fetch_body| {
        // NOTE: you can only fetch the body after it's been downloaded, which might be some time
        // after the initial 'response' (with status code, headers, etc.) has come back. hence this
        // sleep:
        println!("\nDEBUG: Response {:?}", response);
        sleep(Duration::from_millis(100));
        let body = fetch_body().unwrap();
        println!("\nDEBUG: Response body: {:?}", body);
        responses.lock().unwrap().push((response, body));
    }))?;

    // tab.set_default_timeout(Duration::from_secs(100));
    // let final_responses: Vec<_> = responses.lock().unwrap().clone();

    println!("\nTMZ website\n",);
    let jpeg_data = tab
        .navigate_to("https://tmz.com")?
        .wait_until_navigated()?
        .capture_screenshot(ScreenshotFormat::JPEG(Some(75)), None, true)?;
    fs::write("tmz.jpg", &jpeg_data)?;

    println!("\nLobste.rs\n",);
    let jpeg_data = tab
        .navigate_to("http://lobste.rs")?
        .wait_until_navigated()?
        .capture_screenshot(ScreenshotFormat::JPEG(Some(75)), None, true)?;
    fs::write("screenshot.jpg", &jpeg_data)?;

    println!("Screenshots successfully created.");
    Ok(())
}
