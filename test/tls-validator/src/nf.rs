use self::utils::{
    get_server_name, is_client_hello, is_client_key_exchange, is_server_hello, parse_tls_frame, test_extracted_cert,
    tlsf_combine_remove, tlsf_tmp_store, tlsf_update,
};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{codec::Codec, message::Message as TLSMessage};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasherDefault;

use utils;

type FnvHash = BuildHasherDefault<FnvHasher>;
/// The buffer size needs to be chosen wisely.
///
/// The buffer size needs to larger than the largest assembled TLS ServerHello message.
const BUFFER_SIZE: usize = 16384; // 2048, 4096, 8192, 16384

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

    // Temporary payload cache.
    let mut tmp_payload_cache = HashMap::<Flow, Vec<u8>>::with_hasher(Default::default());
    // New map to keep track of the expected seq #
    let mut seqnum_map = HashMap::<Flow, u32>::with_hasher(Default::default());
    // Temporary map to keep track of the expected seq #
    let mut tmp_seqnum_map = HashMap::<Flow, (u32, u32)>::with_hasher(Default::default());
    // TLS connection with invalid certs.
    let mut unsafe_connection: HashSet<Flow> = HashSet::new();
    // DNS name cache.
    let mut name_cache = HashMap::<Flow, webpki::DNSName>::with_hasher(Default::default());

    // Cert count
    let mut cert_count = 0;
    // pkt count
    let mut pkt_count = 0;

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            // FIXME: what is this?!
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
            let _payload_size = p.payload_size();
            info!("");
            info!("TCP Headers: {}", _tcph);

            println!("\nseq # is {:?}\n", _seq);

            println!("\npayload is {:x?}\n", p.get_payload());

            // FIXME: The else part should be written as a filter and it should exec before all these..
            if !unsafe_connection.contains(flow) {
                // check if the flow is recognized
                if payload_cache.contains_key(flow) {
                    info!("Pkt #{} is Occupied!", _seq);
                    info!("And the flow is: {:?}", flow);

                    // The rest of the TLS server hello handshake should be captured here.
                    info!("There is nothing, that is why we should insert the packet!!!");
                    debug!(
                        "Pkt seq # is {}, the expected seq # is {} ",
                        _seq,
                        seqnum_map.get(flow).unwrap()
                    );
                    // Check if this packet is not expected, ie, is a out of order segment.
                    if _seq == *seqnum_map.get(flow).unwrap() {
                        // We received an expected packet
                        debug!("Pkt match expected seq #, update the flow entry...");
                        //debug!("{:?}", p.get_payload());
                        tlsf_update(*flow, payload_cache.entry(*flow), &p.get_payload());
                        seqnum_map.entry(*flow).and_modify(|e| {
                            *e = *e + _payload_size as u32;
                            ()
                        });
                    } else if _seq > *seqnum_map.get(flow).unwrap() {
                        // We received a out-of-order TLS segment
                        debug!("OOO: pkt seq # is larger then expected seq #\n");
                        // We need to check if we should update the entry in the tmp payload cache
                        if tmp_payload_cache.contains_key(flow) {
                            debug!("OOO: we already have entry in the tmp payload cache");
                            // Check if we should update the entry in the tmp payload cache
                            let (entry_pkt_seqno, entry_expected_seqno) = *tmp_seqnum_map.get(flow).unwrap();
                            if _seq == entry_expected_seqno {
                                debug!("OOO: seq # of current pkt matches the expected seq # of the entry in tpc");
                                tlsf_update(*flow, tmp_payload_cache.entry(*flow), &p.get_payload());
                                tmp_seqnum_map
                                    .entry(*flow)
                                    .and_modify(|(entry_pkt_seqno, entry_expected_seqno)| {
                                        *entry_expected_seqno = *entry_expected_seqno + _payload_size as u32;
                                        ()
                                    });
                            } else {
                                info!("Oops: passing because it should be a unrelated packet");
                            }
                        } else {
                            debug!("OOO: We are adding an entry in the tpc!");
                            tmp_seqnum_map.insert(*flow, (_seq, _seq + _payload_size as u32));
                            tmp_payload_cache.insert(*flow, p.get_payload().to_vec());
                        }
                    } else {
                        debug!("Oops: pkt seq # is even smaller then the expected #");
                    }
                } else {
                    info!("Pkt #{} is Vacant", _seq);
                    info!("And the flow is: {:?}", flow);

                    // FIXME: all three checks should be merged into one and return a Option?
                    if is_client_hello(&p.get_payload()) {
                        name_cache.entry(rev_flow).
                            and_modify(|e| { *e  = get_server_name(&p.get_payload()).unwrap() })
                            .or_insert(get_server_name(&p.get_payload()).unwrap());
                    }

                    if is_server_hello(&p.get_payload()) {
                        // NOTE: Matched ServerHello, start inserting packets
                        let buf = [0u8; BUFFER_SIZE];
                        // capture the sequence number
                        debug!("Got ServerHello, insert the flow entry");
                        seqnum_map.insert(*flow, _seq + _payload_size as u32);
                        payload_cache.insert(*flow, p.get_payload().to_vec());
                        //debug!("{:?}", p.get_payload().to_vec());
                    }

                    // The only case that we remove the flow is because we have a ClientKeyExchange
                    // packet.
                    // FIXME: we probably also want to check that the flow is in the payload
                    // cache.
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
                                debug!("OOO: We have OOO segment for this connection");
                                // We have out-of-order segment for this TLS connection.
                                let (tmp_entry_seqnum, _) = tmp_seqnum_map.get(&rev_flow).unwrap();
                                if seqnum_map.get(&rev_flow).unwrap() == tmp_entry_seqnum {
                                    debug!("OOO: We are ready to merge entries in two payload caches together!!!");
                                    if payload_cache.contains_key(&rev_flow)
                                        && tmp_payload_cache.contains_key(&rev_flow)
                                    {
                                        info!("1");
                                        let (_, tmp_entry) = tmp_payload_cache.remove_entry(&rev_flow).unwrap();
                                        info!("size of the tmp entry is {:?}", tmp_entry.len());
                                        info!("2");
                                        let _ = tmp_seqnum_map.remove_entry(&rev_flow);
                                        let _ = seqnum_map.remove_entry(&rev_flow);
                                        info!("3");
                                        let (_, mut e) = payload_cache.remove_entry(&rev_flow).unwrap();
                                        info!("size of the entry is {:?}", e.len());
                                        info!("4");
                                        e.extend(tmp_entry);
                                        info!("size of the merged entry is {:?}", e.len());
                                        info!("5");
                                        let certs = parse_tls_frame(&e);
                                        info!("info: We now retrieve the certs from the tcp payload");
                                        info!("info: flow is {:?}", flow);

                                        match certs {
                                            Ok(chain) => {
                                                debug!("Testing our cert");
                                                let result = test_extracted_cert(chain, dns_name.unwrap());
                                                cert_count = cert_count + 1;
                                                if cert_count % 100000 == 0 {
                                                    println!("cert count is {}", cert_count);
                                                }
                                                if !result {
                                                    debug!("info: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                    unsafe_connection.insert(*flow);
                                                    unsafe_connection.insert(rev_flow);
                                                }
                                            }
                                            Err(e) => {
                                                debug!("ISSUE: match cert incurs error: {:?}\n", e);
                                            }
                                        }
                                    } else {
                                        debug!("ISSUE: Oops, the payload cache doesn't have the entry for this flow");
                                    }
                                } else {
                                    debug!("ISSUE: Oops the expected seq# from our PLC entry doesn't match the seq# from the TPC entry");
                                }
                            } else {
                                info!("No out of order segment for this connection");
                                // Retrieve the payload cache and extract the cert.
                                if payload_cache.contains_key(&rev_flow) {
                                    info!("1");
                                    let (_, e) = payload_cache.remove_entry(&rev_flow).unwrap();
                                    info!("2");
                                    let _ = seqnum_map.remove_entry(&rev_flow);
                                    info!("3");
                                    let certs = parse_tls_frame(&e);
                                    info!("info: We now retrieve the certs from the tcp payload");
                                    info!("info: flow is {:?}", flow);

                                    match certs {
                                        Ok(chain) => {
                                            debug!("Testing our cert");
                                            let result = test_extracted_cert(chain, dns_name.unwrap());

                                            cert_count = cert_count + 1;
                                            if cert_count % 100000 == 0 {
                                                println!("cert count is {}", cert_count);
                                            }
                                            if !result {
                                                debug!("info: Certificate validation failed, both flows' connection need to be reset\n{:?}\n{:?}\n", flow, rev_flow);
                                                unsafe_connection.insert(*flow);
                                                unsafe_connection.insert(rev_flow);
                                            }
                                        }
                                        Err(e) => {
                                            debug!("ISSUE: match cert incurs error: {:?}\n", e);
                                        }
                                    }
                                } else {
                                    debug!("ISSUE: Oops, the payload cache doesn't have the entry for this flow");
                                }
                            }
                        } else {
                            debug!("ISSUE: Oops, we have matched payload cache but we are missing the ClientHello msg!");
                        }
                    } else {
                        info!("Passing because is not Client Key Exchange",);
                    }
                }
            } else {
                // Disabled for now, we can enable it when we are finished.

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
            if pkt_count % 1000000 == 0 {
                // payload_cache.clear();
                // tmp_payload_cache.clear();
                // seqnum_map.clear();
                // tmp_seqnum_map.clear();
                // name_cache.clear();
                // unsafe_connection.clear();
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
