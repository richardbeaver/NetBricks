use e2d2::utils::Flow;
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
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use webpki;
use webpki_roots;

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct CertificateNotExtractedError;

/// Start a TLS flow entry by inserting a TLS frame.
#[allow(dead_code)]
pub fn tlsf_insert(
    flow: Flow,
    payload_cache: &mut HashMap<Flow, Vec<u8>>,
    seqnum_map: &mut HashMap<Flow, u32>,
    payload: &[u8],
    expected_seq: u32,
) {
    payload_cache.insert(flow, payload.to_vec());
    seqnum_map.insert(flow, expected_seq);
}

/// Update a TLS flow entry by updating the entry with continuing TLS frame.
pub fn tlsf_update(flow: Flow, e: Entry<Flow, Vec<u8>>, payload: &[u8]) {
    e.and_modify(|e| {
        debug!("Before writing more bytes {:?}", e.len());
        e.extend(payload);
        debug!("After writing the bytes {:?}", e.len());
        ()
    });
}

/// Remove a TLS flow entry.
#[allow(dead_code)]
pub fn tlsf_remove(e: Entry<Flow, Vec<u8>>) {
    // let buf = match e {
    //     Entry::Vacant(_) => println!("?"),
    //     Entry::Occupied(b) => {
    //         println!("?");
    //         b
    //     }
    // };
    // parse_tls_frame(&buf);
    unimplemented!();
}

#[allow(dead_code)]
pub fn tlsf_tmp_store(
    flow: Flow,
    tmp_payload_cache: &HashMap<Flow, Vec<u8>>,
    tmp_seqnum_map: &HashMap<Flow, u32>,
    payload: &[u8],
) {
    //unimplemented!();
}

/// Remove a TLS flow entry.
#[allow(dead_code)]
pub fn tlsf_combine_remove(
    flow: Flow,
    payload_cache: &HashMap<Flow, Vec<u8>>,
    seqnum_map: &HashMap<Flow, u32>,
    tmp_payload_cache: &HashMap<Flow, Vec<u8>>,
    tmp_seqnum_map: &HashMap<Flow, (u32, u32)>,
) {
    unimplemented!();
}

// FIXME: Allocating too much memory???
pub fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    info!("Matching server name");

    match on_frame(&buf) {
        Some((handshake, _)) => {
            match handshake.payload {
                ClientHello(x) => {
                    //info!("is client hello: {:?}\n", x.extensions);
                    let mut _iterator = x.extensions.iter();
                    let mut result = None;
                    while let Some(val) = _iterator.next() {
                        if ClientExtension::get_type(val) == ExtensionType::ServerName {
                            //info!("Getting a ServerName type {:?}\n", val);
                            let server_name = match val {
                                ClientExtension::ServerName(x) => x,
                                _ => return None,
                            };
                            let ServerName { typ: _, payload: x } = &server_name[0];

                            match x.clone() {
                                ServerNamePayload::HostName(dns_name) => {
                                    info!("DNS name is : {:?}", dns_name);
                                    result = Some(dns_name);
                                }
                                _ => (),
                            }
                        } else {
                            continue;
                        }
                    }
                    info!("info: Result is {:?}", result);
                    info!("info:",);
                    result
                }
                _ => {
                    info!("not client hello",);
                    None
                }
            }
        }
        None => {
            info!("On frame read none bytes",);
            return None;
        }
    }
}

pub fn current_time() -> Result<webpki::Time, TLSError> {
    match webpki::Time::try_from(std::time::SystemTime::now()) {
        Ok(current_time) => Ok(current_time),
        _ => Err(TLSError::FailedToGetCurrentTime),
    }
}

static V: &'static WebPKIVerifier = &WebPKIVerifier { time: current_time };

pub fn test_extracted_cert(certs: Vec<rustls::Certificate>, dns_name: webpki::DNSName) -> bool {
    info!("info: validate certs",);
    debug!("dns name is {:?}\n", dns_name);
    //info!("certs are {:?}\n", certs);
    let mut anchors = RootCertStore::empty();
    anchors.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    //let dns_name = webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
    let result = V.verify_server_cert(&anchors, &certs[..], dns_name.as_ref(), &[]);
    match result {
        Ok(_) => {
            debug!("tlsv result: Valid cert!\n");
            return true;
        }
        Err(e) => {
            debug!("tlsv result: Non valid cert with {}\n", e);
            false
        }
    }
}

/// Parse a slice of bytes into a TLS frame and the size of payload.
pub fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            // info!("\nParsing this TLS frame is \n{:x?}", packet);
            // info!("length of the packet payload is {}\n", packet.payload.length());

            let frame_len = packet.payload.length();
            if packet.typ == ContentType::Handshake && packet.decode_payload() {
                if let MessagePayload::Handshake(x) = packet.payload {
                    Some((x, frame_len))
                } else {
                    info!("Message is not handshake",);
                    None
                }
            } else {
                info!("Packet type doesn't match or we can't decode payload",);
                None
            }
        }
        None => {
            //info!("ON FRAME: Read bytes but got None {:x?}", rest);
            debug!("ON FRAME: Read bytes but got None");
            None
        }
    }
}

/// Test if the current TLS frame is a ServerHello.
pub fn is_server_hello(buf: &[u8]) -> bool {
    info!("Testing for server hello",);
    if on_frame(&buf).is_none() {
        info!("On frame is none");
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ServerHello(_) => {
                info!("is server hello",);
                true
            }
            _ => {
                info!("not server hello",);
                false
            }
        }
    }
}

/// Test if the current TLS frame is a ClientHello.
pub fn is_client_hello(buf: &[u8]) -> bool {
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientHello(_) => {
                info!("is client hello",);
                true
            }
            _ => {
                info!("not client hello",);
                false
            }
        }
    }
}

/// Test if the current TLS frame is ClientKeyExchange.
pub fn is_client_key_exchange(buf: &[u8]) -> bool {
    info!("Testing client key exchange",);
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientKeyExchange(_) => {
                info!("is Client Key Exchange",);
                true
            }
            _ => {
                info!("not Client Key Exchange",);
                false
            }
        }
    }
}

/// Parse the bytes into tls frames.
pub fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>, CertificateNotExtractedError> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    /////////////////////////////////////////////
    //
    //  TLS FRAME One: ServerHello
    //
    /////////////////////////////////////////////

    // match handshake1.payload {
    //     ClientHello(payload) => {
    //         info!("ClientHello",);
    //         info!("{:x?}", payload);
    //     }
    //     ServerHello(payload) => {
    //         info!("{:x?}", payload);
    //     }
    //     _ => info!("None"),
    // }
    let offset1 = match on_frame(&buf) {
        Some((_handshake1, offset1)) => offset1,
        None => return Err(CertificateNotExtractedError),
    };

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    info!("And the magic number is {}\n", offset1 + tls_hdr_len);
    //info!("info: The SECOND TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    // if on_frame(&rest).is_none() {
    //     info!("info: Get None, abort",);
    //     return Err(CertificateNotExtractedError);
    // }
    // let (handshake2, _offset2) = on_frame(&rest).expect("oh no! parsing the Certificate failed!!");

    info!("Working on the second frame...");

    info!("Trying to read the frame using on_frame...");
    let (handshake2, _offset2) = match on_frame(&rest) {
        Some((handshake2, _offset2)) => (handshake2, _offset2),
        None => {
            debug!("Getting the certificate failed, got none");
            return Err(CertificateNotExtractedError);
        }
    };

    let certs = match handshake2.payload {
        CertificatePayload(payload) => {
            //info!("Certificate payload is\n{:x?}", payload);
            info!("Parsing the certificate payload..",);

            Ok(payload)
        }
        _ => {
            info!("None");
            Err(CertificateNotExtractedError)
        }
    };

    // FIXME: we probably don't want to do this...
    return certs;

    let (_, rest) = rest.split_at(_offset2 + tls_hdr_len);
    info!("And the magic number is {}\n", _offset2 + tls_hdr_len);
    info!("The THIRD TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Three: ServerKeyExchange
    //
    /////////////////////////////////////////////

    let (handshake3, offset3) = on_frame(&rest).expect("oh no! parsing the ServerKeyExchange failed!!");

    match handshake3.payload {
        ServerKeyExchange(payload) => info!("Server Key Exchange \n{:x?}", payload), //parse_serverhello(payload, tags),
        _ => info!("None"),
    }

    let (_, rest) = rest.split_at(offset3 + tls_hdr_len);
    info!("And the magic number is {}\n", offset3 + tls_hdr_len);
    info!("The FOURTH TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Four: ServerHelloDone
    //
    /////////////////////////////////////////////

    let (handshake4, offset4) = on_frame(&rest).expect("oh no! parsing the ServerHelloDone failed!!");
    match handshake4.payload {
        ServerHelloDone => info!("Hooray! Server Hello Done!!!"),
        _ => info!("None"),
    }
    info!("And the magic number is {}\n", offset4 + tls_hdr_len);

    certs
}
