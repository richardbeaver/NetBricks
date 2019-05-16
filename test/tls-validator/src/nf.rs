use e2d2::headers::*;
use e2d2::operators::*;
use e2d2::scheduler::*;
use e2d2::state::*;
use e2d2::utils::Flow;
use fnv::FnvHasher;
use rustls::internal::msgs::{
    codec::Codec, enums::ContentType, enums::ServerNameType, handshake::ClientHelloPayload,
    handshake::HandshakePayload, handshake::HasServerExtensions, handshake::ServerHelloPayload,
    handshake::ServerNamePayload, message::Message as TLSMessage, message::MessagePayload,
};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

type FnvHash = BuildHasherDefault<FnvHasher>;

const BUFFER_SIZE: usize = 2048;
const PRINT_SIZE: usize = 256;

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
    // Create the flow cache
    let mut cache = HashMap::<Flow, ReorderedBuffer, FnvHash>::with_hasher(Default::default());

    let mut read_buf: Vec<u8> = (0..PRINT_SIZE).map(|_| 0).collect();

    // group packets into MAC, TCP and UDP packet.
    let mut groups = parent
        .parse::<MacHeader>()
        .transform(box move |p| {
            p.get_mut_header().swap_addresses();
        })
        .parse::<IpHeader>()
        .group_by(
            3,
            box move |p| {
                if p.get_header().protocol() == 6 {
                    0
                } else {
                    1
                }
            },
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
            if !p.get_header().psh_flag() {
                println!("Packet has no Push flag, which means it is a fraction of something!");
                // TODO Check if the packet is part of a TLS handshake
                let flow = p.read_metadata();
                let seq = p.get_header().seq_num();
                match cache.entry(*flow) {
                    Entry::Occupied(mut e) => {
                        let reset = p.get_header().rst_flag();
                        let result = entry.add_data(seq, p.get_payload());
                        println!("Occupied");
                        {
                            let entry = e.get_mut();
                            let result = TLSMessage::read_bytes(&p.get_payload());
                            match result {
                                Some(mut packet) => {
                                    // TODO: need to reassemble tcp segements
                                    if packet.typ == ContentType::Handshake {
                                        println!("Packet match handshake!");
                                        println!("{:?}", packet);
                                    } else {
                                        println!("Packet type is not matched!")
                                    }
                                }
                                None => println!("There is nothing"),
                            }
                        }
                        if reset {
                            // Reset handling.
                            e.remove_entry();
                        }
                    }
                    Entry::Vacant(e) => match ReorderedBuffer::new(BUFFER_SIZE) {
                        Ok(mut b) => {
                            println!("Vacant");
                            {
                                let result = TLSMessage::read_bytes(&p.get_payload());
                                match result {
                                    Some(mut packet) => {
                                        // TODO: need to reassemble tcp segements
                                        if packet.typ == ContentType::Handshake {
                                            println!("Packet match handshake!");
                                            println!("{:?}", packet);
                                        } else {
                                            println!("Packet type is not matched!")
                                        }
                                    }
                                    None => println!("There is nothing"),
                                }
                            }
                        }
                        Err(_) => (),
                    },
                }
            }
        })
        .compose();
    merge(vec![pipe, groups.get_group(1).unwrap().compose()]).compose()
}
