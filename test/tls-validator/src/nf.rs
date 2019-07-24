use self::utils::*;
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use std::io::prelude::*;
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
            let _seq = p.get_header().seq_num();
            let _tcph = p.get_header();
            // FIXME: figure out the correct metric
            let _payload_size = p.payload_size();
            info!("TCP Headers: {}", _tcph);
            pkt_count = pkt_count + 1;
            info!("Total {}", pkt_count);

            // FIXME: The else part should be written as a filter and it should exec before all these..
            if !unsafe_connection.contains(flow) {
                // check if the flow is recognized
                if payload_cache.contains_key(flow) {
                    info!("Pkt #{} is Occupied!", _seq);
                    info!("And the flow is: {:?}", flow);

                    let tls_result = TLSMessage::read_bytes(&p.get_payload());

                    match tls_result {
                        Some(_packet) => {
                            // FIXME: I doubt this part is really necessary. We don't need other
                            // TLS frames, right?
                            info!("Reached handshake packet",);
                        }
                        None => {
                            // The rest of the TLS server hello handshake should be captured here.
                            info!("There is nothing, that is why we should insert the packet!!!\n");

                            // Check if this packet is not expected, ie, is a out of order segment.
                            if _seq == *seqnum_map.get(flow).unwrap() {
                                // We received an expected packet
                                {
                                    tlsf_update(*flow, payload_cache.entry(*flow), &p.get_payload());
                                    seqnum_map.entry(*flow).and_modify(|e| {
                                        *e = *e + _payload_size as u32;
                                        ()
                                    });
                                }
                            } else {
                                // We received a out-of-order TLS segment
                                tlsf_tmp_store(*flow, &tmp_payload_cache, &tmp_seqnum_map, &p.get_payload());
                            }
                        }
                    }
                // the entry for doesn't exist yet--we need to create one first
                } else {
                    info!("Pkt #{} is Vacant", _seq);
                    info!("And the flow is: {:?}", flow);

                    if is_client_hello(&p.get_payload()) {
                        name_cache.insert(rev_flow, get_server_name(&p.get_payload()).unwrap());
                    }

                    if is_server_hello(&p.get_payload()) {
                        // NOTE: Matched ServerHello, start inserting packets
                        let mut buf = [0u8; BUFFER_SIZE];
                        // capture the sequence number
                        {
                            seqnum_map.insert(*flow, _seq);
                            payload_cache.insert(*flow, p.get_payload().to_vec());
                        }
                        // tlsf_insert(
                        //     *flow,
                        //     &mut payload_cache,
                        //     &mut seqnum_map,
                        //     &p.get_payload(),
                        //     _seq + _datal,
                        // );
                    }

                    // The only case that we remove the flow is because we have a ClientKeyExchange
                    // packet.
                    // FIXME: we probably also want to check that the flow is in the payload
                    // chace
                    if is_client_key_exchange(&p.get_payload()) {
                        // We need to retrieve the DNS name from the entry of the current flow, and
                        // also parse the entry for the reverse flow.
                        debug!("important: Pkt {} is a client key exchange\n", _seq);

                        info!("Try to get the dns name from the entry of the {:?}", flow);
                        let dns_name = name_cache.remove(&rev_flow);
                        debug!("Getting the dns name {:?}", dns_name);

                        info!("Try to parse the huge payload of {:?}", rev_flow);
                        if !dns_name.is_none() {
                            if tmp_payload_cache.contains_key(&rev_flow) {
                                debug!("Got out of order segment for this connection");
                                // We have out-of-order segment for this TLS connection.
                                tlsf_combine_remove(
                                    rev_flow,
                                    &payload_cache,
                                    &seqnum_map,
                                    &tmp_payload_cache,
                                    &tmp_seqnum_map,
                                );
                            } else {
                                info!("No out of order segment for this connection");
                                // Retrieve the payload cache and extract the cert.
                                //tlsf_remove(payload_cache.entry(rev_flow));
                                if payload_cache.contains_key(&rev_flow) {
                                    info!("1");
                                    let (_, e) = payload_cache.remove_entry(&rev_flow).unwrap();
                                    info!("2");
                                    let _ = seqnum_map.remove_entry(&rev_flow);
                                    info!("3");
                                    let certs = parse_tls_frame(&e);
                                    info!("info: We now retrieve the certs from the tcp payload\n");

                                    info!("info: flow is {:?}", flow);
                                    match certs {
                                        Ok(chain) => {
                                            debug!("Testing our cert\n");
                                            //info!("chain: {:?}", chain);
                                            // FIXME: it is just a fix, and we definitely need to fix
                                            // the ServerName parsing problem in linux01-all.pcap.
                                            let result = test_extracted_cert(chain, dns_name.unwrap());
                                            cert_count =  cert_count+1;
                                            if cert_count % 10000 == 0{
                                                println!("info: cert count is {}", cert_count);
                                            }
                                            //println!("info: cert count is {}", cert_count);
                                            //println!("info: Result of the cert validation is {}", result);
                                            if !result {
                                                debug!("info: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                unsafe_connection.insert(*flow);
                                                unsafe_connection.insert(rev_flow);
                                            }
                                        }
                                        Err(e) => {
                                            debug!("match cert incurs error: {:?}", e);
                                            //debug!("match cert incurs error");
                                        }
                                    }
                                }
                            }
                        } else {
                            error!("We have matched payload cache but we are missing the ClientHello msg!");
                        }
                    } else {
                        info!("Passing because is not Client Key Exchange",);
                    }
                }
            } else {
                info!("Pkt #{} belong to a unsafe flow!\n", _seq);
                info!("{:?} is marked as unsafe connection so we have to reset\n", flow);
                let _ = unsafe_connection.take(flow);
                let tcph = p.get_mut_header();
                tcph.set_rst_flag();
            }

            // if pkt_count % 100 == 0 {
            //     // check
            //     println!("\nPkt #{}", pkt_count );
            //     println!("payload cache len is {}", payload_cache.len());
            //     println!("seqnum map len is {}", seqnum_map.len());
            //     println!("tmp payload cache len is {}", tmp_payload_cache.len());
            //     println!("tmp seqnum map len is {}", tmp_seqnum_map.len());
            //     println!("name cache len is {}", name_cache.len());
            //     println!("unsafe connection len is {}", unsafe_connection.len());
            // }
            if pkt_count % 100000 == 0 {
                payload_cache.clear();
                tmp_payload_cache.clear();
                seqnum_map.clear();
                tmp_seqnum_map.clear();
                name_cache.clear();
                unsafe_connection.clear();
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
