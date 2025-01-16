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
use aarch64_cpu::{asm, asm::barrier, registers::*};

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

fn print_cache_info() {
    let ctr = CTR_EL0.get();

    info!("CTR_EL0={:x}", ctr);
}

fn calc_shift(level:u32) -> u32 {
    let shift: u32 = 9u32 * ((48u32 - 12u32)/9 - level) + 12;

    shift
}
pub fn read_table_entry(tbl_paddr:u64, idx: u32) -> u64{
    let mut lxentry: u64 = 0;

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

pub fn print_invl_section(level: u32, start_idx: u32, end_idx: u32, vaddr_off: u64) {
    let lxshift = calc_shift(level);
    let start_vaddr: u64 = vaddr_off;
    let end_vaddr: u64 = vaddr_off + (end_idx - start_idx) as u64 * (1u64 << lxshift);

    info!("{1:>0$}L{2}[{3:02}]{4:016x} - {5:016x}: {6} UNDEFINED", (level * 3) as usize, "",
            level, start_idx, start_vaddr, end_vaddr, end_idx - start_idx);
}

pub fn print_section(level: u32, idx: u32, lxentry: u64, vaddr_off: u64) {
    let lxshift = calc_shift(level);
    let start_vaddr: u64 = vaddr_off;
    let end_vaddr: u64 = vaddr_off + (1u64 << lxshift) as u64;

    info!("{1:>0$}L{2}[{3:02}]{4:016x} - {5:016x}: {6:016x}",(level * 3) as usize, "", 
            level, idx, start_vaddr, end_vaddr, lxentry);
}

pub fn print_page_table(level: u32, idx:u32, tbl_paddr: u64, vaddr_off: u64) {
    let lxshift = calc_shift(level - 1);

    info!("{1:>0$}L{2}[{3:02}]{4:016x} - {5:016x}: Table@{6:x}", ((level - 1) * 3) as usize, "", 
            level - 1, idx, vaddr_off, vaddr_off + (1u64 << lxshift), tbl_paddr);

    let mut idx: u32 = 0;
    loop {
        let mut lxentry: u64 = 0;
        let lxshift = calc_shift(level);
        let idx_mask = 0x1ffu64;
        let invl_start_idx: u32;
        let invl_end_idx: u32;
    
        lxentry = read_table_entry(tbl_paddr, idx);
        if (lxentry & 0x01) == 0 {
            invl_start_idx = idx;
            while (lxentry & 0x01) == 0 && idx < 63 {
                idx += 1;
                lxentry = read_table_entry(tbl_paddr, idx);    
            }

            if (lxentry & 0x01) == 0 {
                invl_end_idx = idx + 1;
                print_invl_section(level, invl_start_idx, invl_end_idx, vaddr_off + (1u64 << lxshift)*(invl_start_idx as u64));
                break;
            }
            invl_end_idx = idx;
            print_invl_section(level, invl_start_idx, invl_end_idx, vaddr_off + (1u64 << lxshift)*(invl_start_idx as u64));
        }

        if (lxentry & 0x02) == 0x02 && level < 4 {
            print_page_table(level + 1, idx, lxentry & 0xffff_ffff_f000u64, vaddr_off + (1u64 << lxshift)*(idx as u64));
            idx += 1;
        } else {
            print_section(level, idx, lxentry, vaddr_off + (1u64 << lxshift)*(idx as u64));
            idx += 1;            
        }
        if idx > 63 {
            break;
        }
    }
}

pub fn print_page_tables() {
    let mut ttbr0: u64;
    let mut ttbr1: u64;
    let mut tcr: u64;

    unsafe { asm!("mrs {0}, ttbr0_el2", out(reg)ttbr0); }
    unsafe { asm!("mrs {0}, ttbr1_el2", out(reg)ttbr1); }
    unsafe { asm!("mrs {0}, tcr_el2", out(reg)tcr); }
    info!("page table: tcr_el2={tcr:x} ttbr0_el2={ttbr0:x} ttbr1_el2={ttbr1:x}");

    //print_page_table(1, 0, ttbr0 & 0xffff_ffff_ffe0u64, 0x0);
    print_page_table(1, 1, ttbr1 & 0xffff_ffff_ffe0u64, 0xffff_0000_0000_0000);
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

    print_cache_info();
    print_page_tables();

    let kernel_aspace = new_kernel_aspace().expect("failed to initialize kernel address space");
    debug!("kernel address space init OK: {:#x?}", kernel_aspace);
    KERNEL_ASPACE.init_once(SpinNoIrq::new(kernel_aspace));
    unsafe { axhal::arch::write_page_table_root(kernel_page_table_root()) };

    print_page_tables();

    test_mem_map();
}

/// Initializes kernel paging for secondary CPUs.
pub fn init_memory_management_secondary() {
    unsafe { axhal::arch::write_page_table_root(kernel_page_table_root()) };
}
