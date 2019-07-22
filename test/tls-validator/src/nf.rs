use self::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
//use e2d2::state::{InsertionResult, ReorderedBuffer};
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{codec::Codec, message::Message as TLSMessage};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;

use utils;

type FnvHash = BuildHasherDefault<FnvHasher>;
const BUFFER_SIZE: usize = 16384; // 2048, 4096, 8192, 16384

/// 2. group the same handshake messages into flows
/// 3. defragment the packets into certificate(s)
/// 4. verify that the certificate is valid.
pub fn validator<T: 'static + Batch<Header = NullHeader>, S: Scheduler + Sized>(
    parent: T,
    sched: &mut S,
) -> CompositionBatch {
    /// New payload cache.
    ///
    /// Here impl the new data structure for handling reassembling packets in TCP. Note that it is a
    /// naive implementation of TCP out-of-order segments, for a more comprehensive version you
    /// should visit something like [assembler in
    /// smoltcp](https://github.com/m-labs/smoltcp/blob/master/src/storage/assembler.rs) and [ring
    /// buffer](https://github.com/m-labs/smoltcp/blob/master/src/storage/ring_buffer.rs#L238-L333)
    let mut payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    /// Temporary payload cache.
    let mut tmp_payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());

    /// New map to keep track of the expected seq #
    let mut seqnum_map = HashMap::<Flow, u32>::with_hasher(Default::default());
    /// Temporary map to keep track of the expected seq #
    let mut tmp_seqnum_map = HashMap::<Flow, u32>::with_hasher(Default::default());

    /// TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();
    /// DNS name cache.
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
            // p.get_mut_header().swap_addresses();
            p.get_mut_header();
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
            let _tcph = p.get_header();
            debug!("TCP Headers: {}", _tcph);
            pkt_count = pkt_count + 1;
            debug!("Total {}", pkt_count);
            //let mut seg_len = p.get_header().seg_len();
            //info!("seg length is {}", seg_len);

            if !unsafe_connection.contains(flow) {
                if payload_cache.contains_key(*flow) {
                    // get entry
                    let b = e.get_mut();

                    // TODO: rm later
                    debug!("Pkt #{} is Occupied!", seq);
                    debug!("And the flow is: {:?}", flow);

                    let tls_result = TLSMessage::read_bytes(&p.get_payload());
                    let result = b.add_data(seq, p.get_payload());
                    //info!("Raw payload bytes are: {:x?}\n", p.get_payload());

                    match tls_result {

                        Some(_packet) => {
                            // FIXME: I doubt this part is really necessary.
                            debug!("Reached handshake packet", );
                            //
                            // if packet.typ == ContentType::Handshake {
                            //     info!("We have hit a flow but the current packet match handshake!");
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
                            //     info!("We have hit a flow but the current packet match handshake!");
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
                            debug!("There is nothing, that is why we should insert the packet!!!\n");
                            // FIXME: implement pkt_update
                            match result {
                                InsertionResult::Inserted { available, .. } => {
                                    debug!("Quack: try to insert {}", available);
                                    if available > 0 {
                                        debug!("Inserted");
                                        read_payload(b, available, *flow, &mut payload_cache);
                                    }
                                }
                                InsertionResult::OutOfMemory { written, .. } => {
                                    if written == 0 {
                                        debug!("Resetting since receiving data that is too far ahead");
                                        b.reset();
                                        b.seq(seq, p.get_payload());
                                    }
                                }
                            }
                        }
                    }


                } else {
                    // Vacant means that the entry for doesn't exist yet--we need to create one first
                    debug!("Pkt #{} is Vacant", seq);
                    debug!("And the flow is: {:?}", flow);

                    // TODO: get the server name and store it
                    if is_client_hello(&p.get_payload())  {
                        name_cache.insert(rev_flow, get_server_name(&p.get_payload()).unwrap());
                    }

                    // TODO: we should only create new buffers if it is a server hello.
                    // We only create new buffers if the current flow matches client hello or
                    // server hello.
                    //info!("is server hello?: {}", is_server_hello(&p.get_payload()));
                    //info!("is client hello?: {}\n", is_client_hello(&p.get_payload()));
                    if is_server_hello(&p.get_payload()) {
                        // FIXME: impl with pkt_insert
                        match ReorderedBuffer::new(BUFFER_SIZE) {
                            Ok(mut b) => {
                                debug!("  1: Has allocated a new buffer:");
                                if p.get_header().syn_flag() {
                                    debug!("    2: packet has a syn flag");
                                    seq += 1;
                                } else {
                                    debug!("    2: packet recv for untracked flow did not have a syn flag, skipped");
                                }
                                let result = b.seq(seq, p.get_payload());
                                match result {
                                    InsertionResult::Inserted { available, .. } => {
                                        read_payload(&mut b, available, *flow, &mut payload_cache);
                                        debug!("      4: This packet is inserted, quack");
                                    }
                                    InsertionResult::OutOfMemory { .. } => {
                                        debug!("      4: Too big a packet?");
                                    }
                                }
                                e.insert(b); // this creates the rb_map entry
                            }
                            Err(_) => {
                                debug!("pkt #{} Failed to allocate a buffer for the new flow!", seq);
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
                        debug!("important: Pkt {} is a client key exchange\n", seq);

                        debug!("Try to get the dns name from the entry of the {:?}", flow);
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
                        debug!("Getting the dns name {:?}", dns_name);

                        debug!("Try to parse the huge payload of {:?}", rev_flow);
                        if !dns_name.is_none() {
                            // FIXME: impl pkt_remove
                            match payload_cache.entry(rev_flow) {
                                Entry::Occupied(e) => {
                                    let (_, payload) = e.remove_entry();
                                    //info!("DEBUG: entering parsing the huge payload {:x?}\n", payload);
                                    debug!("DEBUG: entering and then parsing the huge payload \n");
                                    let certs  = parse_tls_frame(&payload);
                                    //info!("DEBUG: We now retrieve the certs from the tcp payload\n{:?}\n", certs);
                                    debug!("DEBUG: We now retrieve the certs from the tcp payload\n");

                                    debug!("DEBUG: flow is {:?}", flow);
                                    match certs {
                                        Ok(chain) => {
                                            debug!("Testing our cert\n");
                                            //info!("chain: {:?}", chain);
                                            // FIXME: it is just a fix, and we definitely need to fix
                                            // the ServerName parsing problem in linux01-all.pcap.
                                            let result = test_extracted_cert(chain, dns_name.unwrap());
                                            cert_count =  cert_count+1;
                                            if cert_count % 100 == 0{
                                                info!("DEBUG: cert count is {}", cert_count);
                                            }
                                            //println!("DEBUG: cert count is {}", cert_count);
                                            //println!("DEBUG: Result of the cert validation is {}", result);
                                            if !result {
                                                debug!("DEBUG: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                unsafe_connection.insert(*flow);
                                                unsafe_connection.insert(rev_flow);
                                            }
                                        }
                                        Err(e) => {
                                            debug!("DEBUG: error: {:?}", e)
                                        }

                                    }
                                }
                                Entry::Vacant(_) => {
                                    debug!("DEBUG: We had a problem: the entry of {:?} doesn't exist", rev_flow)
                                }
                            }

                            match payload_cache.entry(*flow) {
                                Entry::Occupied(_e) => debug!("DEBUG: We had a problem"),
                                Entry::Vacant(_) => debug!("Ok"),
                            }
                            match payload_cache.entry(rev_flow) {
                                Entry::Occupied(_e) => debug!("DEBUG: We had another problem"),
                                Entry::Vacant(_) => debug!("Ok"),
                            }
                        }
                    } else {
                        debug!("Passing because is not Client Key Exchange", );
                    }

                    }

            } else {
                debug!("Pkt #{} belong to a unsafe flow!\n", seq);
                debug!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                let _ = unsafe_connection.take(flow);
                let tcph = p.get_mut_header();
                tcph.set_rst_flag();
            }

            if pkt_count % 5 == 0 {
                // // check
                // info!("{}\n", pkt_count % 500);
                // info!("rb map len is {}", rb_map.len());
                // info!("name cache len is {}", name_cache.len());
                // info!("payload cache len is {}", payload_cache.len());
                // info!("Cleared rb map");
                rb_map.clear();
                name_cache.clear();
                unsafe_connection.clear();
            }
            if pkt_count % 5 == 0{
                payload_cache.clear();
            }
        })
    .reset()
    .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
