use e2d2::state::ReorderedBuffer;
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
use std::collections::HashMap;
use webpki;
use webpki_roots;

const READ_SIZE: usize = 16384; // 256, 512, 1024, 2048, 4096, 8192, 16384

// TODO: move to failure crate!
#[derive(Debug, Clone)]
pub struct CertificateNotExtractedError;

/// Start a TLS flow entry by inserting a TLS frame.
pub fn tlsf_insert() {}

/// Update a TLS flow entry by updating the entry with continuing TLS frame.
pub fn tlsf_update() {}

/// Remove a TLS flow entry.
pub fn tlsf_remove() {}

/// Read payload into the payload cache.
pub fn read_payload(rb: &mut ReorderedBuffer, to_read: usize, flow: Flow, payload_cache: &mut HashMap<Flow, Vec<u8>>) {
    debug!(
        "reading size of {} payload into the flow entry \n{:?} \ninto the payload cache (hashmap)\n",
        to_read, flow,
    );
    let mut read_buf = [0; READ_SIZE];
    let mut so_far = 0;
    while to_read > so_far {
        let payload = payload_cache.entry(flow).or_insert(Vec::new());
        let n = rb.read_data(&mut read_buf);
        so_far += n;
        payload.extend(&read_buf[..n]);
        //debug!("{:?}\n", flow);
        //debug!("And the entries of that flow are: {:?}\n", payload);
    }
    debug!("size of the entry is: {}", so_far);
}

// FIXME: Allocating too much memory???
pub fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    debug!("Matching server name");

    match on_frame(&buf) {
        Some((handshake, _)) => {
            match handshake.payload {
                ClientHello(x) => {
                    //debug!("is client hello: {:?}\n", x.extensions);
                    let mut _iterator = x.extensions.iter();
                    let mut result = None;
                    while let Some(val) = _iterator.next() {
                        if ClientExtension::get_type(val) == ExtensionType::ServerName {
                            //debug!("Getting a ServerName type {:?}\n", val);
                            let server_name = match val {
                                ClientExtension::ServerName(x) => x,
                                _ => return None,
                            };
                            let ServerName { typ: _, payload: x } = &server_name[0];

                            match x.clone() {
                                ServerNamePayload::HostName(dns_name) => {
                                    debug!("DNS name is : {:?}", dns_name);
                                    result = Some(dns_name);
                                }
                                _ => (),
                            }
                        } else {
                            continue;
                        }
                    }
                    debug!("DEBUG: Result is {:?}", result);
                    debug!("DEBUG:",);
                    result
                }
                _ => {
                    debug!("not client hello",);
                    None
                }
            }
        }
        None => {
            debug!("On frame read none bytes",);
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
    debug!("DEBUG: validate certs",);
    debug!("dns name is {:?}\n", dns_name);
    //debug!("certs are {:?}\n", certs);
    let mut anchors = RootCertStore::empty();
    anchors.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    //let dns_name = webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
    let result = V.verify_server_cert(&anchors, &certs[..], dns_name.as_ref(), &[]);
    match result {
        Ok(_) => {
            debug!("DEBUG: \nIt worked!!!");
            return true;
        }
        Err(e) => {
            debug!("DEBUG: \nOops, error: {}", e);
            false
        }
    }
}

/// Parse a slice of bytes into a TLS frame and the size of payload.
pub fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            // debug!("\nParsing this TLS frame is \n{:x?}", packet);
            // debug!("length of the packet payload is {}\n", packet.payload.length());

            let frame_len = packet.payload.length();
            if packet.typ == ContentType::Handshake && packet.decode_payload() {
                if let MessagePayload::Handshake(x) = packet.payload {
                    Some((x, frame_len))
                } else {
                    debug!("Message is not handshake",);
                    None
                }
            } else {
                debug!("Packet type doesn't match or we can't decode payload",);
                None
            }
        }
        None => {
            //debug!("ON FRAME: Read bytes but got None {:x?}", rest);
            debug!("ON FRAME: Read bytes but got None");
            None
        }
    }
}

/// Test if the current TLS frame is a ServerHello.
pub fn is_server_hello(buf: &[u8]) -> bool {
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ServerHello(_) => {
                debug!("is server hello",);
                true
            }
            _ => {
                debug!("not server hello",);
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
                debug!("is client hello",);
                true
            }
            _ => {
                debug!("not client hello",);
                false
            }
        }
    }
}

/// Test if the current TLS frame is ClientKeyExchange.
pub fn is_client_key_exchange(buf: &[u8]) -> bool {
    debug!("Testing client key exchange",);
    if on_frame(&buf).is_none() {
        return false;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientKeyExchange(_) => {
                debug!("is Client Key Exchange",);
                true
            }
            _ => {
                debug!("not Client Key Exchange",);
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
    //         debug!("ClientHello",);
    //         debug!("{:x?}", payload);
    //     }
    //     ServerHello(payload) => {
    //         debug!("{:x?}", payload);
    //     }
    //     _ => debug!("None"),
    // }
    let offset1 = match on_frame(&buf) {
        Some((_handshake1, offset1)) => offset1,
        None => return Err(CertificateNotExtractedError),
    };

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    debug!("And the magic number is {}\n", offset1 + tls_hdr_len);
    //debug!("DEBUG: The SECOND TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    // if on_frame(&rest).is_none() {
    //     debug!("DEBUG: Get None, abort",);
    //     return Err(CertificateNotExtractedError);
    // }
    // let (handshake2, _offset2) = on_frame(&rest).expect("oh no! parsing the Certificate failed!!");
    let (handshake2, _offset2) = match on_frame(&rest) {
        Some((handshake2, _offset2)) => (handshake2, _offset2),
        None => return Err(CertificateNotExtractedError),
    };

    let certs = match handshake2.payload {
        CertificatePayload(payload) => {
            //debug!("Certificate payload is\n{:x?}", payload);
            debug!("Parsing the certificate payload..",);

            Ok(payload)
        }
        _ => {
            debug!("None");
            Err(CertificateNotExtractedError)
        }
    };

    // FIXME: we probably don't want to do this...
    return certs;

    let (_, rest) = rest.split_at(_offset2 + tls_hdr_len);
    debug!("And the magic number is {}\n", _offset2 + tls_hdr_len);
    debug!("The THIRD TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Three: ServerKeyExchange
    //
    /////////////////////////////////////////////

    let (handshake3, offset3) = on_frame(&rest).expect("oh no! parsing the ServerKeyExchange failed!!");

    match handshake3.payload {
        ServerKeyExchange(payload) => debug!("Server Key Exchange \n{:x?}", payload), //parse_serverhello(payload, tags),
        _ => debug!("None"),
    }

    let (_, rest) = rest.split_at(offset3 + tls_hdr_len);
    debug!("And the magic number is {}\n", offset3 + tls_hdr_len);
    debug!("The FOURTH TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Four: ServerHelloDone
    //
    /////////////////////////////////////////////

    let (handshake4, offset4) = on_frame(&rest).expect("oh no! parsing the ServerHelloDone failed!!");
    match handshake4.payload {
        ServerHelloDone => debug!("Hooray! Server Hello Done!!!"),
        _ => debug!("None"),
    }
    debug!("And the magic number is {}\n", offset4 + tls_hdr_len);

    certs
}
