use e2d2::headers::*;
use e2d2::operators::*;

#[inline]
pub fn tcp_nf<T: 'static + Batch<Header = NullHeader>>(parent: T) -> CompositionBatch {
    parent
        .parse::<MacHeader>()
        .map(box |pkt| {
            println!("MAC Header: {}", pkt.get_header());
            let payload = pkt.get_payload();
            print!("MAC Payload: ");
            for p in payload {
                print!("{:x} ", p);
            }
            println!("");
        })
        .parse::<IpHeader>()
        .map(box |pkt| {
            let hdr = pkt.get_header();
            let flow = hdr.flow().unwrap();
            let payload = pkt.get_payload();
            println!("IP Header {} ihl {} offset {}", hdr, hdr.ihl(), hdr.offset());
            println!(
                "IP Payload: {:x} {:x} {:x} {:x}",
                payload[0], payload[1], payload[2], payload[3]
            );
            let (src, dst) = (flow.src_port, flow.dst_port);
            println!("Src port: {} Dst port: {}", src, dst);
        })
        .parse::<UdpHeader>()
        .map(box |pkt| {
            println!("UDP Header: {}", pkt.get_header());
        })
        .compose()
}
