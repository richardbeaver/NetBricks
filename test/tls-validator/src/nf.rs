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

            // FIXME: The else part should be written as a filter and it should exec before all these..
            if !unsafe_connection.contains(flow) {
                // check if the flow is recognized
                if payload_cache.contains_key(*flow) {
                    debug!("Pkt #{} is Occupied!", seq);
                    debug!("And the flow is: {:?}", flow);

                    let tls_result = TLSMessage::read_bytes(&p.get_payload());

                    match tls_result {
                        Some(_packet) => {
                            // FIXME: I doubt this part is really necessary. We don't need other
                            // TLS frames, right?
                            debug!("Reached handshake packet",);
                        }
                        // NOTE: #679 and #103 are matched and inserted here
                        None => {
                            // The rest of the TLS server hello handshake should be captured here.
                            debug!("There is nothing, that is why we should insert the packet!!!\n");
                            // FIXME: implement pkt_update
                            tlsf_update();
                        }
                    }
                // the entry for doesn't exist yet--we need to create one first
                } else {
                    debug!("Pkt #{} is Vacant", seq);
                    debug!("And the flow is: {:?}", flow);

                    if is_client_hello(&p.get_payload()) {
                        name_cache.insert(rev_flow, get_server_name(&p.get_payload()).unwrap());
                        break;
                    }

                    if is_server_hello(&p.get_payload()) {
                        tlsf_insert();
                        break;
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
                        let dns_name = name_cache.remove(&rev_flow);
                        debug!("Getting the dns name {:?}", dns_name);

                        debug!("Try to parse the huge payload of {:?}", rev_flow);
                        if !dns_name.is_none() {
                            tlsf_remove();
                        }
                    } else {
                        debug!("Passing because is not Client Key Exchange",);
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
                // info!("name cache len is {}", name_cache.len());
                // info!("payload cache len is {}", payload_cache.len());
                name_cache.clear();
                unsafe_connection.clear();
            }
            if pkt_count % 5 == 0 {
                payload_cache.clear();
            }
        })
        .reset()
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
