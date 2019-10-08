// use e2d2::utils::Flow;
use failure::Fallible;
use headless_chrome::browser::tab::RequestInterceptionDecision;
use headless_chrome::protocol::network::methods::RequestPattern;
// use headless_chrome::protocol::network::Cookie;
// use headless_chrome::protocol::runtime::methods::{RemoteObjectSubtype, RemoteObjectType};
// use headless_chrome::protocol::RemoteError;
use headless_chrome::LaunchOptionsBuilder;
use headless_chrome::{
    //    protocol::browser::{Bounds, WindowState},
    //    protocol::page::ScreenshotFormat,
    Browser,
    Tab,
};
use rshttp::{HttpHeader, HttpHeaderName, HttpRequest};
use rustls::internal::msgs::{
    codec::Codec,
    enums::{ContentType, ExtensionType},
    handshake::HandshakePayload::{
        Certificate as CertificatePayload, ClientHello, ClientKeyExchange, ServerHello, ServerHelloDone,
        ServerKeyExchange,
    },
    handshake::{ClientExtension, ServerName, ServerNamePayload},
    message::{Message as TLSMessage, MessagePayload},
};
use rustls::{ProtocolVersion, RootCertStore, ServerCertVerifier, TLSError, WebPKIVerifier};
// use std::collections::hash_map::Entry;
// use std::collections::HashMap;
// use std::convert::TryFrom;
// use std::fs;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct HttpRequestNotExtractedError;

/// Parse a slice of bytes into a HTTP frame and the size of payload.
#[allow(dead_code)]
pub fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            // println!("\nParsing this TLS frame is \n{:x?}", packet);
            // println!("length of the packet payload is {}\n", packet.payload.length());

            let frame_len = packet.payload.length();
            if packet.typ == ContentType::Handshake && packet.decode_payload() {
                if let MessagePayload::Handshake(x) = packet.payload {
                    Some((x, frame_len))
                } else {
                    println!("Message is not handshake",);
                    None
                }
            } else {
                println!("Packet type doesn't match or we can't decode payload",);
                None
            }
        }
        None => {
            //println!("ON FRAME: Read bytes but got None {:x?}", rest);
            debug!("ON FRAME: Read bytes but got None");
            None
        }
    }
}

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct CertificateNotExtractedError;

// FIXME: Allocating too much memory???
#[allow(dead_code)]
pub fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    println!("Matching server name");

    match on_frame(&buf) {
        Some((handshake, _)) => {
            match handshake.payload {
                ClientHello(x) => {
                    //println!("is client hello: {:?}\n", x.extensions);
                    let mut _iterator = x.extensions.iter();
                    let mut result = None;
                    while let Some(val) = _iterator.next() {
                        if ClientExtension::get_type(val) == ExtensionType::ServerName {
                            //println!("Getting a ServerName type {:?}\n", val);
                            let server_name = match val {
                                ClientExtension::ServerName(x) => x,
                                _ => return None,
                            };
                            let ServerName { typ: _, payload: x } = &server_name[0];

                            match x.clone() {
                                ServerNamePayload::HostName(dns_name) => {
                                    println!("DNS name is : {:?}", dns_name);
                                    result = Some(dns_name);
                                }
                                _ => (),
                            }
                        } else {
                            continue;
                        }
                    }
                    println!("println: Result is {:?}", result);
                    println!("println:",);
                    result
                }
                _ => {
                    println!("not client hello",);
                    None
                }
            }
        }
        None => {
            println!("On frame read none bytes",);
            return None;
        }
    }
}

/// Test if the current TLS frame is a ServerHello.
#[allow(dead_code)]
pub fn is_server_hello(buf: &[u8]) -> bool {
    println!("Testing for server hello",);
    if on_frame(&buf).is_none() {
        println!("On frame is none");
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ServerHello(_) => {
                println!("is server hello",);
                true
            }
            _ => {
                println!("not server hello",);
                false
            }
        }
    }
}

/// Test if the current TLS frame is a ClientHello.
#[allow(dead_code)]
pub fn is_client_hello(buf: &[u8]) -> bool {
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientHello(_) => {
                println!("is client hello",);
                true
            }
            _ => {
                println!("not client hello",);
                false
            }
        }
    }
}

/// Test if the current TLS frame is ClientKeyExchange.
#[allow(dead_code)]
pub fn is_client_key_exchange(buf: &[u8]) -> bool {
    println!("Testing client key exchange",);
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientKeyExchange(_) => {
                println!("is Client Key Exchange",);
                true
            }
            _ => {
                println!("not Client Key Exchange",);
                false
            }
        }
    }
}

/// Parse the bytes into tls frames.
#[allow(dead_code)]
pub fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>, CertificateNotExtractedError> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    /////////////////////////////////////////////
    //
    //  TLS FRAME One: ServerHello
    //
    /////////////////////////////////////////////

    let offset1 = match on_frame(&buf) {
        Some((_handshake1, offset1)) => offset1,
        None => return Err(CertificateNotExtractedError),
    };

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    println!("And the magic number is {}\n", offset1 + tls_hdr_len);
    //println!("println: The SECOND TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    println!("Working on the second frame...");

    println!("Trying to read the frame using on_frame...");
    let (handshake2, _offset2) = match on_frame(&rest) {
        Some((handshake2, _offset2)) => (handshake2, _offset2),
        None => {
            debug!("Getting the certificate failed, got none");
            return Err(CertificateNotExtractedError);
        }
    };

    let certs = match handshake2.payload {
        CertificatePayload(payload) => {
            //println!("Certificate payload is\n{:x?}", payload);
            println!("Parsing the certificate payload..",);

            Ok(payload)
        }
        _ => {
            println!("None");
            Err(CertificateNotExtractedError)
        }
    };

    // FIXME: we probably don't want to do this...
    return certs;

    let (_, rest) = rest.split_at(_offset2 + tls_hdr_len);
    println!("And the magic number is {}\n", _offset2 + tls_hdr_len);
    println!("The THIRD TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Three: ServerKeyExchange
    //
    /////////////////////////////////////////////

    let (handshake3, offset3) = on_frame(&rest).expect("oh no! parsing the ServerKeyExchange failed!!");

    match handshake3.payload {
        ServerKeyExchange(payload) => println!("Server Key Exchange \n{:x?}", payload), //parse_serverhello(payload, tags),
        _ => println!("None"),
    }

    let (_, rest) = rest.split_at(offset3 + tls_hdr_len);
    println!("And the magic number is {}\n", offset3 + tls_hdr_len);
    println!("The FOURTH TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Four: ServerHelloDone
    //
    /////////////////////////////////////////////

    let (handshake4, offset4) = on_frame(&rest).expect("oh no! parsing the ServerHelloDone failed!!");
    match handshake4.payload {
        ServerHelloDone => println!("Hooray! Server Hello Done!!!"),
        _ => println!("None"),
    }
    println!("And the magic number is {}\n", offset4 + tls_hdr_len);

    certs
}

pub fn prev_tab_create(hostname: String) -> Fallible<()> {
    // Create a headless browser, navigate to wikipedia.org, wait for the page
    // to render completely, take a screenshot of the entire page
    // in JPEG-format using 75% quality.
    println!("RDR entry point",);
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    println!("RDR browser",);
    let tab = browser.wait_for_initial_tab()?;
    println!("RDR tab",);

    println!("RDR entry point",);
    let options2 = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser2 = Browser::new(options2)?;
    println!("RDR browser",);
    let tab2 = browser2.wait_for_initial_tab()?;
    println!("RDR tab",);

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
            trace!("\nDEBUG: url content: {:?}", intercepted.request.url);
            trace!("\nDEBUG: {:?}", intercepted.request);
            if intercepted.request.url.ends_with(".js") {
                trace!("DEBUG: jackpot! We have JS code",);
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

    println!("RDR tab enable request",);

    let responses = Arc::new(Mutex::new(Vec::new()));

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

    println!("RDR tab enable response",);

    println!("\nhostname is: {:?}\n", hostname);
    // let jpeg_data = tab.navigate_to(&hostname)?.wait_until_navigated()?;

    let http_hostname = "http://".to_string() + &hostname;

    // let jpeg_data = tab.navigate_to(&http_hostname)?.wait_until_navigated()?;
    let jpeg_data = tab.navigate_to(&http_hostname)?;

    Ok(())
}

#[allow(dead_code)]
pub fn prev_tab_create_unwrap(hostname: String) {
    // Create a headless browser, navigate to wikipedia.org, wait for the page
    // to render completely, take a screenshot of the entire page
    // in JPEG-format using 75% quality.
    println!("RDR entry point",);
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");
    println!("RDR options",);
    let browser = Browser::new(options).unwrap();
    println!("RDR browser",);
    let tab = browser.wait_for_initial_tab().unwrap();
    println!("RDR tab",);

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
    )
    .unwrap();
    println!("RDR tab enable request",);

    let responses = Arc::new(Mutex::new(Vec::new()));

    tab.enable_response_handling(Box::new(move |response, fetch_body| {
        // NOTE: you can only fetch the body after it's been downloaded, which might be some time
        // after the initial 'response' (with status code, headers, etc.) has come back. hence this
        // sleep:
        println!("\nDEBUG: Response {:?}", response);
        sleep(Duration::from_millis(100));
        let body = fetch_body().unwrap();
        println!("\nDEBUG: Response body: {:?}", body);
        responses.lock().unwrap().push((response, body));
    }))
    .unwrap();

    println!("RDR tab enable response",);

    // hostname is String,
    println!("\nHostname: {:?}\n", hostname);
    let http_hostname = "http://".to_string() + &hostname;
    let jpeg_data = tab.navigate_to(&http_hostname).unwrap().wait_until_navigated().unwrap();
}

pub fn extract_http_request(payload: &[u8]) -> Result<String, HttpRequestNotExtractedError> {
    // if the first three bytes are "GET" or "POS", there's a chance the packet is HTTP
    // if the first three bytes are 0x16, 0x30, 0x00-0x03, there's a chance the packet is TLS

    let get: &[u8] = &[71, 69, 84]; // GET
    let post: &[u8] = &[80, 79, 83]; // POS
    let http: &[u8] = &[72, 84, 84]; // HTT
    let tls0: &[u8] = &[22, 3, 0];
    let tls1: &[u8] = &[22, 3, 1];
    let tls2: &[u8] = &[22, 3, 2];
    let tls3: &[u8] = &[22, 3, 3];

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
                println!("\nImportant: issuing a HTTP request for {:?}", h.value);
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
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.wait_for_initial_tab()?;

    // ONLY TEST
    // let http_hostname = "http://lobste.rs".to_string();
    // let data = tab.navigate_to(&http_hostname).unwrap().wait_until_navigated().unwrap();

    Ok(browser)
}

pub fn tab_create() -> Fallible<Arc<Tab>> {
    let options = LaunchOptionsBuilder::default()
        .build()
        .expect("Couldn't find appropriate Chrome binary.");

    let browser = Browser::new(options)?;
    let tab = browser.new_tab()?;

    // ONLY TEST
    let http_hostname = "http://lobste.rs".to_string();
    let data = tab.navigate_to(&http_hostname).unwrap().wait_until_navigated().unwrap();

    Ok(tab)
}

pub fn retrieve_bulk_pairs(
    hostname: String,
    current_browser: Browser,
    payload_cache: HashMap<Flow, Vec<u8>>,
) -> Fallible<Browser> {
    // Doesn't use incognito mode
    //
    // let current_tab = current_browser.new_tab()?;

    // Incogeneto mode
    //
    let incognito_cxt = current_browser.new_context()?;
    let current_tab: Arc<Tab> = incognito_cxt.new_tab()?;

    println!("bulk1",);

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

    current_tab.enable_request_interception(
        &patterns,
        Box::new(|transport, session_id, intercepted| {
            if intercepted.request.url.ends_with(".js") {
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

    println!("bulk1",);
    let responses = Arc::new(Mutex::new(Vec::new()));

    current_tab.enable_response_handling(Box::new(move |response, fetch_body| {
        // NOTE: you can only fetch the body after it's been downloaded, which might be some time
        // after the initial 'response' (with status code, headers, etc.) has come back. hence this
        // sleep:
        sleep(Duration::from_millis(100));
        let body = fetch_body().unwrap();
        responses.lock().unwrap().push((response, body));
    }))?;

    println!("RDR tab enable response",);

    // This is a hack
    if hostname == "wikia.com" {
        let hostname = "lobste.rs";
        println!("Changed wikia to lobsters",);

        println!("\nDEBUG: Hostname: {:?}", hostname);
        let http_hostname = "http://".to_string() + &hostname;
        println!("Break",);

        let data = current_tab.navigate_to(&http_hostname)?.wait_until_navigated()?;

        println!("OK",);
        return Ok(current_browser);
    }

    println!("\nDEBUG: Hostname: {:?}", hostname);
    let http_hostname = "http://".to_string() + &hostname;
    println!("Break",);

    let data = current_tab.navigate_to(&http_hostname)?.wait_until_navigated()?;

    println!("OK",);
    Ok(current_browser)
}
