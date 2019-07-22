//! ReorderedBuffer implements a buffer data structure to handle out-of-order segments in TCP.
//!
//! However the current implementation has scalability issue. To impl the new data structure for
//! handling reassembling packets in TCP. Note that it is a naive implementation of TCP
//! out-of-order segments, for a more comprehensive version you should visit something like
//! [assembler in
//! smoltcp](https://github.com/m-labs/smoltcp/blob/master/src/storage/assembler.rs) and [ring
//! buffer](https://github.com/m-labs/smoltcp/blob/master/src/storage/ring_buffer.rs#L238-L333)

#[cfg_attr(feature = "dev", allow(module_inception))]
mod reordered_buffer;

pub use self::reordered_buffer::*;
