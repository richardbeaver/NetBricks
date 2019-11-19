use self::utils::{do_client_key_exchange, get_server_name, on_frame, tlsf_update};
use e2d2::headers::{IpHeader, MacHeader, NullHeader, TcpHeader};
use e2d2::operators::{merge, Batch, CompositionBatch};
use e2d2::scheduler::Scheduler;
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::handshake::HandshakePayload::{ClientHello, ClientKeyExchange, ServerHello};
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
    // New payload cache.
    //
    // Here impl the new data structure for handling reassembling packets in TCP. Note that it is a
    // naive implementation of TCP out-of-order segments, for a more comprehensive version you
    // should visit something like [assembler in
    // smoltcp](https://github.com/m-labs/smoltcp/blob/master/src/storage/assembler.rs) and [ring
    // buffer](https://github.com/m-labs/smoltcp/blob/master/src/storage/ring_buffer.rs#L238-L333)
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

            pkt_count += 1;
            info!("");
            info!("TCP Headers: {}", _tcph);

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
                            let (_, entry_expected_seqno) = *tmp_seqnum_map.get(flow).unwrap();
                            if _seq == entry_expected_seqno {
                                debug!("OOO: seq # of current pkt matches the expected seq # of the entry in tpc");
                                tlsf_update(*flow, tmp_payload_cache.entry(*flow), &p.get_payload());
                                tmp_seqnum_map.entry(*flow).and_modify(|(_, entry_expected_seqno)| {
                                    *entry_expected_seqno = *entry_expected_seqno + _payload_size as u32;
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

                    let handshake = match on_frame(&p.get_payload()) {
                        Some((handshake, _)) => handshake,
                        None => return,
                    };

                    match handshake.payload {
                        ClientHello(_) => {
                            name_cache
                                .entry(rev_flow)
                                .and_modify(|e| *e = get_server_name(&p.get_payload()).unwrap())
                                .or_insert(get_server_name(&p.get_payload()).unwrap());
                        }
                        ServerHello(_) => {
                            // capture the sequence number
                            debug!("Got ServerHello, insert the flow entry");
                            seqnum_map.insert(*flow, _seq + _payload_size as u32);
                            payload_cache.insert(*flow, p.get_payload().to_vec());
                        }
                        ClientKeyExchange(_) => {
                            let dns_name = name_cache.remove(&rev_flow);
                            match dns_name {
                                Some(name) => do_client_key_exchange(
                                    name,
                                    flow,
                                    &rev_flow,
                                    &mut cert_count,
                                    &mut unsafe_connection,
                                    &mut tmp_payload_cache,
                                    &mut tmp_seqnum_map,
                                    &mut payload_cache,
                                    &mut seqnum_map,
                                ),
                                None => info!("We are missing the dns name from the client hello",),
                            }
                        }
                        _ => return,
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
