use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::state::{InsertionResult, ReorderedBuffer};
use e2d2::utils::Flow;
use fnv::FnvHasher;
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
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;
use webpki;
use webpki_roots;

// TODO: move to failure crate!!!
// Define our error types. These may be customized for our error handling cases.
// Now we will be able to write our own errors, defer to an underlying error
// implementation, or do something in between.
#[derive(Debug, Clone)]
struct CertificateNotExtractedError;

type FnvHash = BuildHasherDefault<FnvHasher>;
const BUFFER_SIZE: usize = 4096; // 2048
const READ_SIZE: usize = 512; // 256

fn get_server_name(buf: &[u8]) -> Option<webpki::DNSName> {
    info!("Matching server name");

    if on_frame(&buf).is_none() {
        info!("On frame read none bytes",);
        return None;
    } else {
        let (handshake, _) = on_frame(&buf).unwrap();

        match handshake.payload {
            ClientHello(x) => {
                //info!("\nis client hello: {:?}\n", x.extensions);
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
                info!("DEBUG: Result is {:?}", result);
                info!("DEBUG:",);
                result
            }
            _ => {
                info!("not client hello",);
                None
            }
        }
    }
}

fn current_time() -> Result<webpki::Time, TLSError> {
    match webpki::Time::try_from(std::time::SystemTime::now()) {
        Ok(current_time) => Ok(current_time),
        _ => Err(TLSError::FailedToGetCurrentTime),
    }
}

static V: &'static WebPKIVerifier = &WebPKIVerifier { time: current_time };

fn test_extracted_cert(certs: Vec<rustls::Certificate>, dns_name: webpki::DNSName) -> bool {
    info!("DEBUG: validate certs",);
    info!("\ndns name is {:?}\n", dns_name);
    //info!("\ncerts are {:?}\n", certs);
    let mut anchors = RootCertStore::empty();
    anchors.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    //let dns_name = webpki::DNSNameRef::try_from_ascii_str("github.com").unwrap();
    let result = V.verify_server_cert(&anchors, &certs[..], dns_name.as_ref(), &[]);
    match result {
        Ok(_) => {
            info!("DEBUG: \nIt worked!!!");
            return true;
        }
        Err(e) => {
            info!("DEBUG: \nOops, error: {}", e);
            false
        }
    }
}

/// Read payload into the payload cache.
fn read_payload(rb: &mut ReorderedBuffer, to_read: usize, flow: Flow, payload_cache: &mut HashMap<Flow, Vec<u8>>) {
    info!(
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
        //info!("\n{:?}\n", flow);
        //info!("\nAnd the entries of that flow are: {:?}\n", payload);
    }
    info!("size of the entry is: {}", so_far);
}

/// Parse a slice of bytes into a TLS frame and the size of payload.
fn on_frame(rest: &[u8]) -> Option<(rustls::internal::msgs::handshake::HandshakeMessagePayload, usize)> {
    match TLSMessage::read_bytes(&rest) {
        Some(mut packet) => {
            // info!("\n\nParsing this TLS frame is \n{:x?}", packet);
            // info!("\nlength of the packet payload is {}\n", packet.payload.length());

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
            //info!("\nON FRAME: Read bytes but got None {:x?}", rest);
            info!("\nON FRAME: Read bytes but got None");
            None
        }
    }
}

/// Test if the current TLS frame is a ServerHello.
fn is_server_hello(buf: &[u8]) -> bool {
    if on_frame(&buf).is_none() {
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
fn is_client_hello(buf: &[u8]) -> bool {
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
fn is_client_key_exchange(buf: &[u8]) -> bool {
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
fn parse_tls_frame(buf: &[u8]) -> Result<Vec<rustls::Certificate>, CertificateNotExtractedError> {
    // TLS Header length is 5.
    let tls_hdr_len = 5;
    let mut _version = ProtocolVersion::Unknown(0x0000);

    /////////////////////////////////////////////
    //
    //  TLS FRAME One: ServerHello
    //
    /////////////////////////////////////////////

    let (handshake1, offset1) = on_frame(&buf).expect("oh no!  parsing the ServerHello failed!!");

    //use self::HandshakePayload::*;
    match handshake1.payload {
        ClientHello(payload) => {
            info!("ClientHello",);
            info!("{:x?}", payload);
        }
        ServerHello(payload) => {
            info!("ServerHello",);
            info!("{:x?}", payload);
        }
        _ => info!("None"),
    }

    let (_, rest) = buf.split_at(offset1 + tls_hdr_len);
    info!("\nAnd the magic number is {}\n", offset1 + tls_hdr_len);
    //info!("DEBUG: The SECOND TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Two: Certificate
    //
    /////////////////////////////////////////////

    if on_frame(&rest).is_none() {
        info!("DEBUG: Get None, abort",);
        return Err(CertificateNotExtractedError);
    }
    let (handshake2, _offset2) = on_frame(&rest).expect("oh no! parsing the Certificate failed!!");

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
    info!("\nAnd the magic number is {}\n", _offset2 + tls_hdr_len);
    info!("The THIRD TLS frame starts with: {:x?}", rest);

    /////////////////////////////////////////////
    //
    //  TLS FRAME Three: ServerKeyExchange
    //
    /////////////////////////////////////////////

    let (handshake3, offset3) = on_frame(&rest).expect("oh no! parsing the ServerKeyExchange failed!!");

    match handshake3.payload {
        ServerKeyExchange(payload) => info!("\nServer Key Exchange \n{:x?}", payload), //parse_serverhello(payload, tags),
        _ => info!("None"),
    }

    let (_, rest) = rest.split_at(offset3 + tls_hdr_len);
    info!("\nAnd the magic number is {}\n", offset3 + tls_hdr_len);
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
    info!("\nAnd the magic number is {}\n", offset4 + tls_hdr_len);

    certs
}

/// TLS validator:
///
/// 1. identify TLS handshake messages.
/// 2. group the same handshake messages into flows
/// 3. defragment the packets into certificate(s)
/// 4. verify that the certificate is valid.
pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let mut rb_map = HashMap::<Flow, ReorderedBuffer, FnvHash>::with_hasher(Default::default());

    // Payload cache
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // List of TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();

    // Unfortunately we have to store the previous flow as a state here, and initialize it with a
    // bogus flow.
    // let mut prev_flow = Flow {
    //     src_ip: 0,
    //     dst_ip: 0,
    //     src_port: 0,
    //     dst_port: 0,
    //     proto: 0,
    // };

    // Cert count
    let mut cert_count = 0;
    // pkt count
    let mut pkt_count = 0;

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            // FIXME: what is this>
            p.get_mut_header().swap_addresses();
        })
        .parse::<IpHeader>()
        .group_by(
            2,
            box move |p| if p.get_header().protocol() == 6 { 0 } else { 1 },
            sched,
        );

    // Create the pipeline--we perform the actual packet processing here.
    let pipe = groups
        .get_group(0)
        .unwrap()
        .metadata(box move |p| {
            let flow = p.get_header().flow().unwrap();
            flow
        })
    .parse::<TcpHeader>()
        .transform(box move |p| {
            let flow = p.read_metadata();
            let rev_flow = flow.reverse_flow();
            let mut seq = p.get_header().seq_num();
            let tcph = p.get_header();
            info!("\n\nTCP Headers: {}", tcph);
            pkt_count = pkt_count + 1;
            println!("Total {}", pkt_count);
            //let mut seg_len = p.get_header().seg_len();
            //info!("seg length is {}", seg_len);
            if !unsafe_connection.contains(flow) {
                match rb_map.entry(*flow) {
                    // occupied means that there already exists an entry for the flow
                    Entry::Occupied(mut e) => {
                        // get entry
                        let b = e.get_mut();

                        // TODO: rm later
                        info!("\nPkt #{} is Occupied!", seq);
                        info!("And the flow is: {:?}", flow);
                        //info!("Previous one is: {:?}", prev_flow);
                        //info!("Reverse of the current one is: {:?}\n", rev_flow);

                        let tls_result = TLSMessage::read_bytes(&p.get_payload());
                        let result = b.add_data(seq, p.get_payload());
                        //info!("Raw payload bytes are: {:x?}\n", p.get_payload());

                        match tls_result {
                            Some(packet) => {
                                //info!("Now the packet length is {:?}", packet.length());
                                if packet.typ == ContentType::Handshake {
                                    info!("\nWe have hit a flow but the current packet match handshake!");
                                    info!("Suppect to be starting a new TLS handshake, we should remove the hash value and start again");
                                    //info!("{:x?}", packet);
                                    match result {
                                        InsertionResult::Inserted { available, .. } => {
                                            info!("Try to insert {}", available);
                                            if available > 0 {
                                                info!("Inserted");
                                                read_payload(b, available, *flow, &mut payload_cache);
                                            }
                                        }
                                        InsertionResult::OutOfMemory { written, .. } => {
                                            if written == 0 {
                                                info!("Resetting since receiving data that is too far ahead");
                                                b.reset();
                                                b.seq(seq, p.get_payload());
                                            }
                                        }
                                    }
                                } else {
                                    // FIXME: we want to insert this packet anyway
                                    info!("Packet type doesn't match a handshake, however we still need to insert this packet?");
                                    info!("\nWe have hit a flow but the current packet match handshake!");
                                    info!("Suppect to be starting a new TLS handshake, we should remove the hash value and start again");
                                    //info!("{:x?}", packet);
                                    match result {
                                        InsertionResult::Inserted { available, .. } => {
                                            info!("Try to insert {}", available);
                                            if available > 0 {
                                                info!("Inserted");
                                                read_payload(b, available, *flow, &mut payload_cache);
                                            }
                                        }
                                        InsertionResult::OutOfMemory { written, .. } => {
                                            if written == 0 {
                                                info!("Resetting since receiving data that is too far ahead");
                                                b.reset();
                                                b.seq(seq, p.get_payload());
                                            }
                                        }
                                    }


                                }
                            }
                            // NOTE: #679 and #103 are matched and inserted here
                            None => {
                                // The rest of the TLS server hello handshake should be captured here.
                                info!("\nThere is nothing, that is why we should insert the packet!!!\n");
                                match result {
                                    InsertionResult::Inserted { available, .. } => {
                                        info!("Quack: try to insert {}", available);
                                        if available > 0 {
                                            info!("Inserted");
                                            read_payload(b, available, *flow, &mut payload_cache);
                                        }
                                    }
                                    InsertionResult::OutOfMemory { written, .. } => {
                                        if written == 0 {
                                            info!("Resetting since receiving data that is too far ahead");
                                            b.reset();
                                            b.seq(seq, p.get_payload());
                                        }
                                    }
                                }
                            }
                        }

                        // The only case that we remove the flow is because we have a ChangeClientSpec
                        // packet.
                        if is_client_key_exchange(&p.get_payload()) {
                            // We need to retrieve the DNS name from the entry of the current flow, and
                            // also parse the entry for the reverse flow.
                            info!("\nimportant: Pkt {} is a client key exchange\n", seq);

                            info!("Try to get the dns name from the entry of the {:?}", flow);
                            let dns_name = match payload_cache.entry(*flow) {
                                Entry::Occupied(e) => {
                                    let (_, payload) = e.remove_entry();
                                    //info!("And the payload is {:x?}", payload);
                                    get_server_name(&payload)
                                }
                                Entry::Vacant(_) => {
                                    info!("We had a problem: there is not entry of the ClientHello", );
                                    None
                                }
                            };
                            info!("ServerName is: {:?}", dns_name);

                            info!("Try to parse the huge payload of {:?}", rev_flow);
                            match payload_cache.entry(rev_flow) {
                                Entry::Occupied(e) => {
                                    let (_, payload) = e.remove_entry();
                                    //info!("\nDEBUG: entering parsing the huge payload {:x?}\n", payload);
                                    info!("\nDEBUG: entering and then parsing the huge payload \n");
                                    let certs  = parse_tls_frame(&payload);
                                    //info!("\nDEBUG: We now retrieve the certs from the tcp payload\n{:?}\n", certs);
                                    info!("\nDEBUG: We now retrieve the certs from the tcp payload\n");

                                    info!("DEBUG: flow is {:?}", flow);
                                    match certs {
                                        Ok(chain) => {
                                            info!("\nTesting our cert\n");
                                            //info!("chain: {:?}", chain);
                                            // FIXME: it is just a fix, and we definitely need to fix
                                            // the ServerName parsing problem in linux01-all.pcap.
                                            if dns_name.is_none() {
                                                info!("DEBUG: DNS name not found, droping" );
                                            } else {
                                                let result = test_extracted_cert(chain, dns_name.unwrap());
                                                cert_count =  cert_count+1;
                                                info!("DEBUG: cert count is {}", cert_count);
                                                info!("DEBUG: Result of the cert validation is {}", result);
                                                if !result {
                                                    info!("DEBUG: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                    unsafe_connection.insert(*flow);
                                                    unsafe_connection.insert(rev_flow);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            info!("DEBUG: error: {:?}", e)
                                        }

                                    }
                                }
                                Entry::Vacant(_) => {
                                    info!("DEBUG: We had a problem: the entry of {:?} doesn't exist", rev_flow)
                                }
                            }

                            match payload_cache.entry(*flow) {
                                Entry::Occupied(_e) =>info!("DEBUG: We had a problem"),
                                Entry::Vacant(_) => info!("Ok"),
                            }
                            match payload_cache.entry(rev_flow) {
                                Entry::Occupied(_e) => info!("DEBUG: We had another problem"),
                                Entry::Vacant(_) => info!("Ok"),
                            }
                        } else {
                            info!("Passing because is not Client Key Exchange", );
                        }
                    }
                    // Vacant means that the entry for doesn't exist yet--we need to create one first
                    Entry::Vacant(e) => {
                        info!("\nPkt #{} is Vacant", seq);
                        info!("\nAnd the flow is: {:?}", flow);
                        //info!("Previous one is: {:?}", prev_flow);

                        if is_client_hello(&p.get_payload())  {
                            info!("ClientHello");
                            get_server_name(&p.get_payload());
                        }
                        // We only create new buffers if the current flow matches client hello or
                        // server hello.
                        //info!("\nis server hello?: {}", is_server_hello(&p.get_payload()));
                        //info!("is client hello?: {}\n", is_client_hello(&p.get_payload()));
                        if is_client_hello(&p.get_payload()) || is_server_hello(&p.get_payload()) {
                            match ReorderedBuffer::new(BUFFER_SIZE) {
                                Ok(mut b) => {
                                    info!("  1: Has allocated a new buffer:");
                                    if p.get_header().syn_flag() {
                                        info!("    2: packet has a syn flag");
                                        seq += 1;
                                    } else {
                                        info!("    2: packet recv for untracked flow did not have a syn flag, skipped");
                                    }
                                    let result = b.seq(seq, p.get_payload());
                                    match result {
                                        InsertionResult::Inserted { available, .. } => {
                                            read_payload(&mut b, available, *flow, &mut payload_cache);
                                            info!("      4: This packet is inserted, quack");
                                        }
                                        InsertionResult::OutOfMemory { .. } => {
                                            info!("      4: Too big a packet?");
                                        }
                                    }
                                    e.insert(b);
                                }
                                Err(_) => {
                                    info!("\npkt #{} Failed to allocate a buffer for the new flow!", seq);
                                    ()
                                }
                            }
                        }
                    }
                }
            } else {
                info!("\nPkt #{} belong to a unsafe flow!\n", seq);
                info!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                let _ = unsafe_connection.take(flow);
                let tcph = p.get_mut_header();
                tcph.set_rst_flag();
            }
        })
    .reset()
    .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
