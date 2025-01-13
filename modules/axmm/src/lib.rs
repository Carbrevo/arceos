//! [ArceOS](https://github.com/arceos-org/arceos) memory management module.

#![no_std]

#[macro_use]
extern crate log;
extern crate alloc;

mod aspace;

pub use self::aspace::AddrSpace;

use axerrno::{AxError, AxResult};
use axhal::mem::phys_to_virt;
use axhal::paging::PagingError;
use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use memory_addr::{va, PhysAddr};
use core::arch::asm;

static KERNEL_ASPACE: LazyInit<SpinNoIrq<AddrSpace>> = LazyInit::new();

fn paging_err_to_ax_err(err: PagingError) -> AxError {
    warn!("Paging error: {:?}", err);
    match err {
        PagingError::NoMemory => AxError::NoMemory,
        PagingError::NotAligned => AxError::InvalidInput,
        PagingError::NotMapped => AxError::NotFound,
        PagingError::AlreadyMapped => AxError::AlreadyExists,
        PagingError::MappedToHugePage => AxError::InvalidInput,
    }
}

/// Creates a new address space for kernel itself.
pub fn new_kernel_aspace() -> AxResult<AddrSpace> {
    let mut aspace = AddrSpace::new_empty(
        va!(axconfig::KERNEL_ASPACE_BASE),
        axconfig::KERNEL_ASPACE_SIZE,
    )?;
    for r in axhal::mem::memory_regions() {
        aspace.map_linear(phys_to_virt(r.paddr), r.paddr, r.size, r.flags.into())?;
    }
    Ok(aspace)
}

pub fn test_mem_map() {
    let mut s1paddr: u64;
    let mut s2paddr: u64;
    let mut max_vaddr: u64 = 0;
    let mut max_paddr: u64 = 0;

    unsafe {
        let mut sctlr_el2: u64;
        let mut ttbr0_el2: u64;
        let mut ttbr1_el2: u64;

        asm!("mrs {sctlr_el2}, sctlr_el2",
            "mrs {ttbr0_el2}, ttbr0_el2",
            "mrs {ttbr1_el2}, ttbr1_el2",
            sctlr_el2 = out(reg)sctlr_el2,
            ttbr0_el2 = out(reg)ttbr0_el2,
            ttbr1_el2 = out(reg)ttbr1_el2
        );
        info!("test_mem_map: system regs: sctlr_el2={:x} ttbr0_el2={:x} ttbr1_el2={:x}",
                sctlr_el2, ttbr0_el2, ttbr1_el2);
    }
    for r in axhal::mem::memory_regions() {
        let mut cur_vaddr: u64 = usize::from(phys_to_virt(r.paddr)) as u64;
        let mut cur_paddr: u64 = usize::from(r.paddr) as u64;
            if max_vaddr < cur_vaddr {
            max_vaddr = cur_vaddr;
            max_paddr = cur_paddr;
        }
        unsafe {
            asm!("at s1e1r, {paddr}",
            "isb",
            "mrs {s1paddr}, PAR_EL1",
            "at s1e2r, {paddr}",
            "isb",
            "mrs {s2paddr}, PAR_EL1",
            paddr = in(reg)usize::from(phys_to_virt(r.paddr)),
            s1paddr = lateout(reg)s1paddr,
            s2paddr = lateout(reg)s2paddr
        );
        }
        //aspace.map_linear(phys_to_virt(r.paddr), r.paddr, r.size, r.flags.into())?;
        info!("test_mem_map: {:x}:{:x} -> {s1paddr:x} -> {s2paddr:x}", usize::from(phys_to_virt(r.paddr)), usize::from(r.paddr));

        unsafe {
            let mut l0entry: u64 = 0;
            let mut l1entry: u64 = 0;
            let mut l2entry: u64 = 0;
    
            asm!("mrs {l0entry}, ttbr1_el2",
                "mov {tmp}, xzr",
                "bfxil {tmp}, {l0entry}, #5, #43",
                "lsl {tmp}, {tmp}, #5",
                "bfxil {idx}, {vaddr}, #38, #9",
                "add {tmp}, {tmp}, {idx}, LSL #3",
                "at s1e2r, {tmp}",
                "isb",
                "mrs {idx}, par_el1",
                "tst {idx}, #1",
                "b.ne 1f",
                "ldr {l1entry}, [{tmp}]",
                "mov {tmp}, xzr",
                "bfxil {tmp}, {l1entry}, #12, #48",
                "lsl {tmp}, {tmp}, #12",
                "bfxil {idx}, {vaddr}, #29, #9",
                "add {tmp}, {tmp}, {idx}, LSL #3",
                "at s1e2r, {tmp}",
                "isb",
                "mrs {idx}, par_el1",
                "tst {idx}, #1",
                "b.ne 2f",
                "ldr {l2entry}, [{tmp}]",
                "b 3f",
                "1: mov {l1entry}, {idx}",
                "mov {l2entry}, xzr",
                "b 3f",
                "2: mov {l2entry}, {idx}",
                "b 3f",
                "3:",
                vaddr = in(reg)cur_vaddr,
                tmp = out(reg) _,
                idx = out(reg) _,
                l0entry = out(reg)l0entry,
                l1entry = out(reg)l1entry,
                l2entry = out(reg)l2entry
            );
            info!("trans {:x}:{:x}: L0:{l0entry:x}[{}] -> L1:{l1entry:x}[{}] -> L2:{l2entry:x}",
                    cur_vaddr, cur_paddr,
                    (cur_vaddr >> 12 + 9 * 3) & 63,
                    (cur_vaddr >> 12 + 9 * 2) & 63,

                );
        }
    }
}

pub fn read_table_entry(tbl_paddr:u64, idx: usize) -> u64{
    let lxentry: u64 = 0;

    unsafe {
        asm!("",
            "add {paddr}, {paddr}, {idx}, LSL #3",
            "ldr {lxentry}, [{paddr}]",
            paddr = in(reg)tbl_paddr,
            idx = in(reg)idx,
            lxentry = lateout(reg)lxentry
        );
    }
    lxentry
}

pub fn print_invl_section(level: i32, start_idx: i32, end_idx: i32, vaddr_off: u64) {
    info!("")
}

pub fn print_page_table(level: i32, tbl_paddr: u64, vaddr_off: u64) {
    let idx: i32 = 0;
    loop {
        let mut lxentry: u64 = 0;
        let calc_shift = |lvl|{ 9u64 * ((48 - 12)/9 - lvl) + 12 };
        let mut lxshift = calc_shift(level);
        let idx_mask = 0x1ffu64;
        let calc_idx;
        let mut invl_start_idx: i32 = -1;
        let mut invl_end_idx: i32;
    
        lxentry = read_table_entry(tbl_paddr, idx);
        if (lxentry & 0x01) == 0 {
            invl_start_idx = idx;
            while (lxentry & 0x01) == 0 && idx < 63 {
                idx += 1;
                lxentry = read_table_entry(tbl_paddr, idx);    
            }

            if (lxentry & 0x01) == 0 {
                invl_end_idx = idx;
                print_invl_section(level, invl_start_idx, invl_end_idx);
                break;
            }
            invl_end_idx = idx - 1;
            print_invl_section(level, invl_start_idx, invl_end_idx);
        }

        if (lxentry & 0x02) == 1 {
            print_page_table(level + 1, lxentry & 0xffff_ffff_f000u64, vaddr_off);
        } else {
            print_section(level, idx, lxentry, vaddr_off + (1u64 << lxshift)*idx);
        }
    }
}

pub fn print_page_tables() {
    let mut ttbr0: u64;
    let mut ttbr1: u64;

    unsafe { asm!("mrs {0}, ttbr0_el2", out(reg)ttbr0); }
    unsafe { asm!("mrs {0}, ttbr1_el2", out(reg)ttbr1); }
    info!("ttbr0_el2={ttbr0_el2:x} ttbr1_el2={ttbr1_el2:x}");

    print_page_table(1, ttbr0 & 0xffff_ffff_ffe0u64, 0x0);
    print_page_table(1, ttbr1 & 0xffff_ffff_ffe0u64, 0xffff_0000_0000);
}


/// Returns the globally unique kernel address space.
pub fn kernel_aspace() -> &'static SpinNoIrq<AddrSpace> {
    &KERNEL_ASPACE
}

/// Returns the root physical address of the kernel page table.
pub fn kernel_page_table_root() -> PhysAddr {
    KERNEL_ASPACE.lock().page_table_root()
}

/// Initializes virtual memory management.
///
/// It mainly sets up the kernel virtual memory address space and recreate a
/// fine-grained kernel page table.
pub fn init_memory_management() {
    info!("Initialize virtual memory management...");

    let kernel_aspace = new_kernel_aspace().expect("failed to initialize kernel address space");
    debug!("kernel address space init OK: {:#x?}", kernel_aspace);
    KERNEL_ASPACE.init_once(SpinNoIrq::new(kernel_aspace));
    unsafe { axhal::arch::write_page_table_root(kernel_page_table_root()) };
    test_mem_map();
}

/// Initializes kernel paging for secondary CPUs.
pub fn init_memory_management_secondary() {
    unsafe { axhal::arch::write_page_table_root(kernel_page_table_root()) };
}
