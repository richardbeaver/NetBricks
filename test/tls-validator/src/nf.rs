use self::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::state::{InsertionResult, ReorderedBuffer};
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{codec::Codec, enums::ContentType, message::Message as TLSMessage};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;

use utils;

type FnvHash = BuildHasherDefault<FnvHasher>;
const BUFFER_SIZE: usize = 8192; // 2048, 4096, 8192

/// 2. group the same handshake messages into flows
/// 3. defragment the packets into certificate(s)
/// 4. verify that the certificate is valid.
pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    let mut rb_map = HashMap::<Flow, ReorderedBuffer, FnvHash>::with_hasher(Default::default());

    // Payload cache.
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();
    // DNS name.
    let mut name_cache = HashMap::<Flow, webpki::DNSName>::with_hasher(Default::default());

    // Cert count
    let mut cert_count = 0;
    // pkt count
    let mut pkt_count = 0;

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            // FIXME: what is this
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
            //info!("\nTCP Headers: {}", tcph);
            pkt_count = pkt_count + 1;
            //println!("Total {}", pkt_count);
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

                        let tls_result = TLSMessage::read_bytes(&p.get_payload());
                        let result = b.add_data(seq, p.get_payload());
                        //info!("Raw payload bytes are: {:x?}\n", p.get_payload());

                        match tls_result {

                            Some(packet) => {
                                // FIXME: I doubt this part is really necessary.
                                info!("Reached handshake packet", );
                                //
                                // if packet.typ == ContentType::Handshake {
                                //     info!("\nWe have hit a flow but the current packet match handshake!");
                                //     info!("Suppect to be starting a new TLS handshake, we should remove the hash value and start again");
                                //     //info!("{:x?}", packet);
                                //     match result {
                                //         InsertionResult::Inserted { available, .. } => {
                                //             info!("Try to insert {}", available);
                                //             if available > 0 {
                                //                 info!("Inserted");
                                //                 read_payload(b, available, *flow, &mut payload_cache);
                                //             }
                                //         }
                                //         InsertionResult::OutOfMemory { written, .. } => {
                                //             if written == 0 {
                                //                 info!("Resetting since receiving data that is too far ahead");
                                //                 b.reset();
                                //                 b.seq(seq, p.get_payload());
                                //             }
                                //         }
                                //     }
                                // } else {
                                //     info!("Reached non-handshake packet", );
                                //
                                //     // FIXME: we want to insert this packet anyway
                                //     info!("Packet type doesn't match a handshake, however we still need to insert this packet?");
                                //     info!("\nWe have hit a flow but the current packet match handshake!");
                                //     info!("Suppect to be starting a new TLS handshake, we should remove the hash value and start again");
                                //     //info!("{:x?}", packet);
                                //     match result {
                                //         InsertionResult::Inserted { available, .. } => {
                                //             info!("Try to insert {}", available);
                                //             if available > 0 {
                                //                 info!("Inserted");
                                //                 read_payload(b, available, *flow, &mut payload_cache);
                                //             }
                                //         }
                                //         InsertionResult::OutOfMemory { written, .. } => {
                                //             if written == 0 {
                                //                 info!("Resetting since receiving data that is too far ahead");
                                //                 b.reset();
                                //                 b.seq(seq, p.get_payload());
                                //             }
                                //         }
                                //     }
                                // }
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


                    }
                    // Vacant means that the entry for doesn't exist yet--we need to create one first
                    Entry::Vacant(e) => {
                        info!("\nPkt #{} is Vacant", seq);
                        info!("\nAnd the flow is: {:?}", flow);
                        //info!("Previous one is: {:?}", prev_flow);

                        // TODO: get the server name and store it
                        if is_client_hello(&p.get_payload())  {
                            info!("Getting a ClientHello, recording the server name {:?}", get_server_name(&p.get_payload()).unwrap());
                            name_cache.insert(rev_flow, get_server_name(&p.get_payload()).unwrap());
                        }

                        // TODO: we should only create new buffers if it is a server hello.
                        // We only create new buffers if the current flow matches client hello or
                        // server hello.
                        //info!("\nis server hello?: {}", is_server_hello(&p.get_payload()));
                        //info!("is client hello?: {}\n", is_client_hello(&p.get_payload()));
                        if is_server_hello(&p.get_payload()) {
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

                        // The only case that we remove the flow is because we have a ClientKeyExchange
                        // packet.
                        // FIXME: we probably also want to check that the flow is in the payload
                        // chace
                        if is_client_key_exchange(&p.get_payload()) {
                            // We need to retrieve the DNS name from the entry of the current flow, and
                            // also parse the entry for the reverse flow.
                            info!("\nimportant: Pkt {} is a client key exchange\n", seq);

                            info!("Try to get the dns name from the entry of the {:?}", flow);
                            // let dns_name = match payload_cache.entry(*flow) {
                            //     Entry::Occupied(e) => {
                            //         let (_, payload) = e.remove_entry();
                            //         //info!("And the payload is {:x?}", payload);
                            //         get_server_name(&payload)
                            //     }
                            //     Entry::Vacant(_) => {
                            //         info!("We had a problem: there is not entry of the ClientHello", );
                            //         None
                            //     }
                            // };
                            // info!("ServerName is: {:?}", dns_name);
                            let dns_name = name_cache.remove(&rev_flow);
                            info!("\nGetting the dns name {:?}", dns_name);

                            info!("Try to parse the huge payload of {:?}", rev_flow);
                            if !dns_name.is_none() {
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
                                                let result = test_extracted_cert(chain, dns_name.unwrap());
                                                cert_count =  cert_count+1;
                                                //println!("DEBUG: cert count is {}", cert_count);
                                                //println!("DEBUG: Result of the cert validation is {}", result);
                                                if !result {
                                                    info!("DEBUG: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                    unsafe_connection.insert(*flow);
                                                    unsafe_connection.insert(rev_flow);
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
                            }
                        } else {
                            info!("Passing because is not Client Key Exchange", );
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

            if pkt_count % 100 == 0 {
                // // check
                // info!("\n{}\n", pkt_count % 500);
                // info!("rb map len is {}", rb_map.len());
                // info!("name cache len is {}", name_cache.len());
                // info!("payload cache len is {}", payload_cache.len());
                // info!("Cleared rb map");
                rb_map.clear();
                payload_cache.clear();
                name_cache.clear();
                unsafe_connection.clear();
            }
        })
    .reset()
    .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
