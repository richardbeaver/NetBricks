use super::act::Act;
use super::iterator::{BatchIterator, PacketDescriptor};
use super::packet_batch::PacketBatch;
use super::Batch;
use crate::common::*;
use crate::headers::EndOffset;
use crate::headers::NullHeader;
use crate::interface::PacketTx;
use crate::scheduler::Executable;

/// `CompositionBatch` allows multiple NFs to be combined. A composition batch resets the packet pointer so that each NF
/// can treat packets as originating from the NF itself.
pub struct CompositionBatch {
    parent: Box<dyn Batch<Header = NullHeader, Metadata = EmptyMetadata>>,
}

impl CompositionBatch {
    /// Return a composition batch.
    // TODO:doc
    pub fn new<T: EndOffset, M: Sized + Send, V: 'static + Batch<Header = T, Metadata = M>>(
        parent: V,
    ) -> CompositionBatch {
        CompositionBatch {
            parent: box parent.reset(),
        }
    }
}

impl Batch for CompositionBatch {}

impl BatchIterator for CompositionBatch {
    type Header = NullHeader;
    type Metadata = EmptyMetadata;

    #[inline]
    fn start(&mut self) -> usize {
        self.parent.start()
    }

    #[inline]
    unsafe fn next_payload(&mut self, idx: usize) -> Option<PacketDescriptor<NullHeader, EmptyMetadata>> {
        self.parent.next_payload(idx)
    }
}

/// Internal interface for packets.
impl Act for CompositionBatch {
    act! {}
}

impl Executable for CompositionBatch {
    #[inline]
    fn execute(&mut self) {
        self.act();
        self.done();
    }

    #[inline]
    fn dependencies(&mut self) -> Vec<usize> {
        self.get_task_dependencies()
    }
}
