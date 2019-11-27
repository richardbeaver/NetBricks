use failure::Fallible;
use headless_chrome::browser::tab::RequestInterceptionDecision;
use headless_chrome::protocol::network::methods::RequestPattern;
use headless_chrome::protocol::network::{events, methods, Request};
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{Browser, Tab};
use rshttp::{HttpHeaderName, HttpRequest};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct HttpRequestNotExtractedError;

#[derive(Debug, Clone)]
pub struct RequestResponsePair {
    request: Request,
    response_params: events::ResponseReceivedEventParams,
    response_body: methods::GetResponseBodyReturnObject,
}

pub fn extract_http_request(payload: &[u8]) -> Result<String, HttpRequestNotExtractedError> {
    // if the first three bytes are "GET" or "POS", there's a chance the packet is HTTP
    // if the first three bytes are 0x16, 0x30, 0x00-0x03, there's a chance the packet is TLS

    let get: &[u8] = &[71, 69, 84]; // GET
    let _post: &[u8] = &[80, 79, 83]; // POS
    let _http: &[u8] = &[72, 84, 84]; // HTT
    let _tls0: &[u8] = &[22, 3, 0];
    let _tls1: &[u8] = &[22, 3, 1];
    let _tls2: &[u8] = &[22, 3, 2];
    let _tls3: &[u8] = &[22, 3, 3];

    let (head, _) = payload.split_at(3);

    if head == get {
        let payload_str = match std::str::from_utf8(payload) {
            Ok(s) => s.to_string(),
            Err(_) => return Err(HttpRequestNotExtractedError),
        };

        let get_request = HttpRequest::new(&payload_str).unwrap();
        let headers = get_request.headers;

        let mut _iterator = headers.iter();

        while let Some(h) = _iterator.next() {
            if h.name == HttpHeaderName::Host {
                // println!("\nImportant: issuing a HTTP request for {:?}", h.value);
                return Ok(h.value.clone());
            } else {
                continue;
            }
        }
        return Err(HttpRequestNotExtractedError);
    } else {
        Err(HttpRequestNotExtractedError)
    }
}

pub fn browser_create() -> Fallible<Browser> {
    // println!("try to create a browser",);
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let _ = browser.wait_for_initial_tab()?;

    // println!("Browser created",);
    Ok(browser)
}

#[allow(dead_code)]
pub fn tab_create() -> Fallible<Arc<Tab>> {
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.new_tab()?;

    // ONLY TEST
    // let http_hostname = "http://lobste.rs".to_string();
    // let data = tab.navigate_to(&http_hostname).unwrap().wait_until_navigated().unwrap();

    Ok(tab)
}

pub fn retrieve_bulk_pairs(
    hostname: String,
    current_browser: Browser,
) -> Fallible<(
    Browser,
    Vec<Request>,
    Vec<(
        events::ResponseReceivedEventParams,
        methods::GetResponseBodyReturnObject,
    )>,
)> {
    // Doesn't use incognito mode
    //
    // let current_tab = current_browser.new_tab()?;

    // Incogeneto mode
    //
    let incognito_cxt = current_browser.new_context()?;
    let current_tab: Arc<Tab> = incognito_cxt.new_tab()?;

    // println!("try to retrieve bulk",);

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

    let request = Arc::new(Mutex::new(Vec::new()));
    let request2 = request.clone();

    current_tab.enable_request_interception(
        &patterns,
        Box::new(move |_, _, intercepted| {
            request2.lock().unwrap().push(intercepted.request);

            RequestInterceptionDecision::Continue
        }),
    )?;

    let final_request: Vec<_> = request.lock().unwrap().clone();

    // println!("bulk1",);
    let responses = Arc::new(Mutex::new(Vec::new()));
    let responses2 = responses.clone();

    current_tab.enable_response_handling(Box::new(move |response, fetch_body| {
        // NOTE: you can only fetch the body after it's been downloaded, which might be some time
        // after the initial 'response' (with status code, headers, etc.) has come back. hence this
        // sleep:
        sleep(Duration::from_millis(50));

        let body = fetch_body().unwrap();

        responses2.lock().unwrap().push((response, body));
    }))?;

    let final_responses: Vec<_> = responses.lock().unwrap().clone();

    // let http_hostname = "http://".to_string() + &hostname;
    let http_hostname = "https://".to_string() + &hostname;
    let _ = current_tab.navigate_to(&http_hostname)?.wait_until_navigated()?;

    // let request_response_pair = RequestResponsePair {
    //     request: request,
    //     response_params: response_params,
    //     response_body: response_body,
    // };

    println!("retrieve: OK",);
    Ok((current_browser, final_request, final_responses))
}
