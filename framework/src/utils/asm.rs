use std::alloc::System;
use std::arch::asm;
use std::time::SystemTime;
use nix::Error::Sys;

/// Retrieve the CPU ID.
// #[inline]
// pub fn cpuid() {
//     unsafe {
//         llvm_asm!("movl $$0x2, %eax":::"eax");
//         llvm_asm!("movl $$0x0, %ecx":::"ecx");
//         llvm_asm!("cpuid"
//              :
//              :
//              : "rax rbx rcx rdx");
//     }
// }

/// Read the value of the timestamp register (32 bits).
///
/// rdtsc returns timestamp in a pair of 32-bit registers (EDX and EAX).
#[inline]
pub fn rdtsc_unsafe() -> u64 {
    // unsafe {
    //     let low: u32 = 0;
    //     let high: u32 = 0;
    //     asm!("rdtsc"
    //          : "={eax}" (low), "={edx}" (high)
    //          :
    //          : "rdx rax"
    //          : "volatile");
    //     ((high as u64) << 32) | (low as u64)
    // }
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).expect("System time should be after Unix epoch").as_secs()
}

/// Read the value of the timestamp register (64 bits).
///
/// Currently use rdtscp (Read Time-Stamp Counter and Processor ID) because the value of the
/// timestamp register is stored into the `RDX` and `RAX` registers.
// #[inline]
// pub fn rdtscp_unsafe() -> u64 {
//     let high: u32;
//     let low: u32;
//     unsafe {
//         llvm_asm!("rdtscp"
//              : "={eax}" (low), "={edx}" (high)
//              :
//              : "ecx"
//              : "volatile");
//         ((high as u64) << 32) | (low as u64)
//     }
// }

/// Pause instruction.
///
/// Safe because it is similar to a NOP, and has no memory effects
#[inline]
pub fn pause() {
    unsafe {
        asm!("pause");
    }
}
