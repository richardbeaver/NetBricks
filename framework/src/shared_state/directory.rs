//! A directory of shared structures.
use super::{open_shared, SharedMemory};
use crate::utils::PAGE_SIZE;
use std::mem::size_of;
use std::sync::atomic::*;

const MAX_LEN: usize = 256; // 255 byte names
const DIRECTORY_PAGES: usize = 2; // Dedicate 2 pages to the directory.
const BYTE_SIZE: usize = DIRECTORY_PAGES * PAGE_SIZE;

/// Directory header for shared data.
#[repr(align(2), C)]
#[derive(Debug)]
pub struct DirectoryHeader {
    entries: AtomicUsize,
    // Used to signal that snapshotting is in progress.
    current_version: AtomicUsize,
    committed_version: AtomicUsize,
    length: usize,
}

/// Directory entry for shared data.
#[repr(packed, C)]
#[derive(Debug)]
pub struct DirectoryEntry {
    /// Name of the entry.
    pub name: [u8; MAX_LEN],
}

/// A directory of shared structures.
#[derive(Debug)]
pub struct Directory {
    head: *mut DirectoryHeader,
    data: *mut DirectoryEntry,
    // Need this to make sure memory is not dropped
    _shared_memory: SharedMemory<DirectoryHeader>,
    entry: usize,
    len: usize,
}

impl Directory {
    /// Initialize the directory.
    pub fn new(name: &str) -> Directory {
        unsafe {
            let shared = open_shared(name, BYTE_SIZE);
            let head = shared.mem as *mut DirectoryHeader;
            (*head).current_version.store(1, Ordering::SeqCst);
            let header_size = size_of::<DirectoryHeader>();
            let entry_size = size_of::<DirectoryEntry>();
            let entries = (BYTE_SIZE - header_size) / entry_size;
            let entry = (head.offset(1) as *mut u8) as *mut DirectoryEntry;
            (*head).length = entries;
            (*head).entries.store(0, Ordering::Release);
            (*head).committed_version.store(1, Ordering::SeqCst);
            Directory {
                head,
                data: entry,
                _shared_memory: shared,
                entry: 0,
                len: entries,
            }
        }
    }

    /// Register a new entry.
    pub fn register_new_entry(&mut self, name: &str) -> Option<usize> {
        let entry = self.entry;
        if entry >= self.len || name.len() >= MAX_LEN {
            None
        } else {
            unsafe {
                let entry_ptr = self.data.add(entry);
                (*entry_ptr).name.copy_from_slice(name.as_bytes());
                (*self.head).entries.store(entry, Ordering::Release);
            }
            self.entry += 1;
            Some(entry)
        }
    }

    /// Begin the directory.
    #[inline]
    pub fn begin_snapshot(&mut self) {
        unsafe {
            (*self.head).current_version.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// End the directory.
    #[inline]
    pub fn end_snapshot(&mut self) {
        unsafe {
            let version = (*self.head).current_version.load(Ordering::Acquire);
            (*self.head).committed_version.store(version, Ordering::Release);
        }
    }
}
