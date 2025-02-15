//! DPDK utils.

use super::METADATA_SLOTS;
use crate::config::{NetbricksConfiguration, DEFAULT_CACHE_SIZE, DEFAULT_POOL_SIZE};
use crate::native::libnuma;
use crate::native::zcsi;
use std::cell::Cell;
use std::ffi::CString;

/// Initialize the system, whitelisting some set of NICs and allocating mempool of given size.
fn init_system_wl_with_mempool(name: &str, core: i32, pci: &[String], pool_size: u32, cache_size: u32) {
    let name_cstr = CString::new(name).unwrap();
    let pci_cstr: Vec<_> = pci.iter().map(|p| CString::new(&p[..]).unwrap()).collect();
    let mut whitelist: Vec<_> = pci_cstr.iter().map(|p| p.as_ptr()).collect();
    unsafe {
        let ret = zcsi::init_system_whitelisted(
            name_cstr.as_ptr(),
            name.len() as i32,
            core,
            whitelist.as_mut_ptr(),
            pci.len() as i32,
            pool_size,
            cache_size,
            METADATA_SLOTS,
        );
        if ret != 0 {
            panic!("Could not initialize the system errno {}", ret)
        }
    }
}

/// Initialize the system, whitelisting some set of NICs.
pub fn init_system_wl(name: &str, core: i32, pci: &[String]) {
    init_system_wl_with_mempool(name, core, pci, DEFAULT_POOL_SIZE, DEFAULT_CACHE_SIZE);
    set_numa_domain();
}

/// Initialize the system as a DPDK secondary process with a set of VDEVs. User must specify mempool name to use.
pub fn init_system_secondary(name: &str, core: i32) {
    let name_cstr = CString::new(name).unwrap();
    let mut vdev_list = vec![];
    unsafe {
        let ret = zcsi::init_secondary(name_cstr.as_ptr(), name.len() as i32, core, vdev_list.as_mut_ptr(), 0);
        if ret != 0 {
            panic!("Could not initialize secondary process errno {}", ret)
        }
    }
    set_numa_domain();
}

/// Initialize the system based on the supplied scheduler configuration.
pub fn init_system(config: &NetbricksConfiguration) {
    if config.name.is_empty() {
        panic!("Configuration must provide a name.");
    }
    // We init with all devices blacklisted and rely on the attach logic to white list them as necessary.
    if config.secondary {
        // We do not have control over any of the other settings in this case.
        init_system_secondary(&config.name[..], config.primary_core);
    } else {
        init_system_wl_with_mempool(
            &config.name[..],
            config.primary_core,
            &[],
            config.pool_size,
            config.cache_size,
        );
    }
    set_numa_domain();
}

thread_local!(static NUMA_DOMAIN: Cell<i32> = Cell::new(-1));

fn set_numa_domain() {
    let domain = unsafe {
        if libnuma::numa_available() == -1 {
            println!("No NUMA information found, support disabled");
            -1
        } else {
            let domain = libnuma::numa_preferred();
            println!("Running on node {}", domain);
            domain
        }
    };
    NUMA_DOMAIN.with(|f| f.set(domain))
}

/// Affinitize a pthread to a core and assign a DPDK thread ID.
pub fn init_thread(tid: i32, core: i32) {
    let numa = unsafe { zcsi::init_thread(tid, core) };
    NUMA_DOMAIN.with(|f| {
        f.set(numa);
    });
    if numa == -1 {
        println!("No NUMA information found, support disabled");
    } else {
        println!("Running on node {}", numa);
    };
}

/// Get NUMA domain.
#[inline]
pub fn get_domain() -> i32 {
    NUMA_DOMAIN.with(|f| f.get())
}
