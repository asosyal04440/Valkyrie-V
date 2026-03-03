#![allow(dead_code)]
use crate::vmm::{
    evaluate_capabilities,
    atlas::{Atlas, Allocation},
    guest_memory::GuestMemory,
    ipi::IpiController,
    kernel_loader::KernelLoader,
    multiboot2::Multiboot2Loader,
    scheduler,
    vcpu::VcpuState,
    virtio_block::VirtIoBlock,
    virtio_console::VirtIoConsole,
    virtio_mmio::{VirtIoDeviceEnum, VirtIoMmio},
    virtio_net::VirtIoNet,
    vmx::Vmx,
    Capabilities, CapabilityDecision, HvError, HvResult,
};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

// EPT tables are large (4 × 4 KiB per VM) and must not live on the stack.
// Store them in BSS as a static array indexed by VM id.
use crate::vmm::ept::Ept;
static mut EPT_TABLES: [Ept; 16] = [const { Ept::new() }; 16];

/// Returns a mutable reference to the EPT for the given VM slot.
/// # Safety
/// The caller must ensure no two live references to the same slot exist
/// simultaneously (upheld by `VirtualMachine`'s exclusive ownership of its id).
#[inline]
unsafe fn ept_for(id: u32) -> &'static mut Ept {
    &mut EPT_TABLES[id as usize % 16]
}

const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;

/// Read an MSR. Privileged — only callable outside test mode.
#[cfg(not(test))]
#[inline(always)]
fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    }
    ((high as u64) << 32) | low as u64
}

/// In tests, return a value with bit 33 set so EPT appears allowed.
#[cfg(test)]
#[inline(always)]
fn read_msr(_msr: u32) -> u64 {
    1u64 << 33
}

#[cfg(not(test))]
#[inline(always)]
fn monotonic_ticks() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(test)]
#[inline(always)]
fn monotonic_ticks() -> u64 {
    1
}

pub const VIRTIO_MMIO_BASE_NET: u64 = 0x1000_0000;
pub const VIRTIO_MMIO_BASE_BLK: u64 = 0x1001_0000;
pub const VIRTIO_MMIO_BASE_CONSOLE: u64 = 0x1002_0000;
pub const VIRTIO_MMIO_SIZE: u64 = 0x1000;

pub const MAX_VM_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Starting,
    Running,
    Paused,
    Stopping,
    Stopped,
    Error,
}

impl VmState {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Created => 0,
            Self::Starting => 1,
            Self::Running => 2,
            Self::Paused => 3,
            Self::Stopping => 4,
            Self::Stopped => 5,
            Self::Error => 6,
        }
    }

    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Created,
            1 => Self::Starting,
            2 => Self::Running,
            3 => Self::Paused,
            4 => Self::Stopping,
            5 => Self::Stopped,
            _ => Self::Error,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VmConfig {
    pub name: [u8; MAX_VM_NAME_LEN],
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub kernel_path: Option<u64>,
    pub kernel_size: u64,
    pub initrd_path: Option<u64>,
    pub initrd_size: u64,
    pub cmdline: [u8; 256],
    pub cmdline_len: u32,
    pub virtio_net: bool,
    pub virtio_block: bool,
    pub virtio_console: bool,
    pub block_size: u64,
    pub mac_address: [u8; 6],
}

impl VmConfig {
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_VM_NAME_LEN],
            memory_size: 256 * 1024 * 1024,
            vcpu_count: 1,
            kernel_path: None,
            kernel_size: 0,
            initrd_path: None,
            initrd_size: 0,
            cmdline: [0u8; 256],
            cmdline_len: 0,
            virtio_net: true,
            virtio_block: true,
            virtio_console: true,
            block_size: 8 * 1024 * 1024 * 1024,
            mac_address: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
        }
    }

    pub fn set_name(&mut self, name: &str) {
        let len = name.len().min(MAX_VM_NAME_LEN - 1);
        self.name[..len].copy_from_slice(name.as_bytes());
        self.name[len] = 0;
    }

    pub fn set_cmdline(&mut self, cmdline: &str) {
        let len = cmdline.len().min(255);
        self.cmdline[..len].copy_from_slice(cmdline.as_bytes());
        self.cmdline[len] = 0;
        self.cmdline_len = len as u32;
    }
}

impl Default for VmConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VmStats {
    pub vcpu_count: u32,
    pub memory_size: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub disk_reads: u64,
    pub disk_writes: u64,
    pub uptime: u64,
}

impl VmStats {
    pub const fn new() -> Self {
        Self {
            vcpu_count: 0,
            memory_size: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            disk_reads: 0,
            disk_writes: 0,
            uptime: 0,
        }
    }
}

impl Default for VmStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VirtualMachine {
    id: u32,
    config: VmConfig,
    state: AtomicU8,
    guest_memory: GuestMemory,
    kernel_loader: KernelLoader,
    multiboot2_loader: Multiboot2Loader,
    vcpu_state: VcpuState,
    ipi_controller: IpiController,
    virtio_mmio: VirtIoMmio,
    start_time: AtomicU64,
    cpu_time: AtomicU64,
    /// Active VMX context — set when the VM is running.
    vmx: Option<Vmx>,
    /// Atlas allocation backing this VM's guest RAM.
    /// Stored here so it can be returned on `delete_vm`.
    host_allocation: Option<Allocation>,
    /// Boot info address (Multiboot2 or Linux boot_params)
    boot_info_addr: AtomicU64,
}

impl VirtualMachine {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            config: VmConfig::new(),
            state: AtomicU8::new(VmState::Created as u8),
            guest_memory: GuestMemory::new(),
            kernel_loader: KernelLoader::new(),
            multiboot2_loader: Multiboot2Loader::new(),
            vcpu_state: VcpuState::new(),
            ipi_controller: IpiController::new(),
            virtio_mmio: VirtIoMmio::new(),
            start_time: AtomicU64::new(0),
            cpu_time: AtomicU64::new(0),
            vmx: None,
            host_allocation: None,
            boot_info_addr: AtomicU64::new(0),
        }
    }

    /// Configure the VM using a pre-allocated host memory region.
    ///
    /// `host_base`: physical address of the start of guest RAM.
    /// `host_size`: total size in bytes of the allocated region.
    ///
    /// When `host_base != 0` (real hardware path via Atlas), the guest
    /// memory is zeroed for security before any data is written.
    pub fn configure_with_allocation(
        &mut self,
        config: VmConfig,
        host_base: u64,
        host_size: u64,
    ) -> HvResult<()> {
        self.config = config;

        self.guest_memory.init(host_base, host_size)?;

        // Zero guest RAM to prevent information leakage between VMs.
        if host_base != 0 {
            let _ = self.guest_memory.zero_range(0, host_size.min(self.guest_memory.memory_limit()));
        }

        let vcpu_count = self.config.vcpu_count.min(64);
        
        // Initialize scheduler with number of vCPUs
        scheduler::init_scheduler(1); // Start with 1 pCPU, will expand with SMP
        
        for i in 0..vcpu_count {
            let vcpu = self.vcpu_state
                .create_vcpu(i)
                .ok_or(HvError::LogicalFault)?;
            
            // Allocate VPID for each vCPU
            if !vcpu.allocate_vpid() {
                return Err(HvError::LogicalFault);
            }
            
            // Set default priority and affinity
            // BSP (vCPU 0) gets slightly higher priority
            if i == 0 {
                vcpu.set_affinity(0, 2); // Hard affinity to pCPU 0 for BSP
            } else {
                vcpu.set_affinity(0, 0); // No affinity for APs initially
            }
        }

        // Write multi-CPU ACPI MADT when we have more than 1 vCPU.
        if vcpu_count > 1 && host_base != 0 {
            self.guest_memory.write_guest_acpi_tables_for_cpus(vcpu_count)?;
        }

        if self.config.virtio_block {
            let blk = VirtIoBlock::new(self.config.block_size);
            self.virtio_mmio.set_device(VirtIoDeviceEnum::Block(blk));
        }

        if self.config.virtio_net {
            let net = VirtIoNet::new();
            self.virtio_mmio.set_device(VirtIoDeviceEnum::Net(net));
        }

        if self.config.virtio_console {
            let console = VirtIoConsole::new(80, 25);
            self.virtio_mmio
                .set_device(VirtIoDeviceEnum::Console(console));
        }

        // Build identity EPT mapping for the entire guest RAM region.
        unsafe { ept_for(self.id) }
            .map_range_huge(0, self.config.memory_size)
            .map_err(|_| HvError::LogicalFault)?;

        // Write CPU boot tables into guest RAM so the processor can operate
        // in 64-bit long mode from the first instruction.
        //   GDT at 0x500   (VMCS GDTR_BASE=0x500)
        //   PTs at 0x1000  (VMCS CR3=0x1000)  — identity-mapped 2 MiB pages
        //   IDT at 0x7000  (VMCS IDTR_BASE will be set to 0x7000)
        // These writes require a real guest RAM backing (host_base != 0).
        // In test mode (host_base == 0) they are no-ops.
        if self.guest_memory.host_base() != 0 {
            self.guest_memory.write_guest_gdt()?;
            self.guest_memory.write_guest_page_tables()?;
            self.guest_memory.write_guest_idt_stub()?;
            self.guest_memory.write_guest_acpi_tables()?;
        }

        // Wire VirtIO DMA engine to real guest RAM so that descriptor
        // addresses (GPAs) resolve directly instead of bouncing through
        // the 64 KiB side buffer.
        if self.guest_memory.host_base() != 0 {
            crate::vmm::virtio_direct().set_guest_backing(
                self.guest_memory.host_base(),
                self.guest_memory.memory_limit(),
            );
        }

        // Write boot_params (E820 table, etc.) to guest RAM at BOOT_PARAMS_BASE
        // so the Linux kernel finds a valid memory map on entry.
        {
            use crate::vmm::guest_memory::BOOT_PARAMS_BASE;
            let boot_params = self
                .kernel_loader
                .get_boot_params(&self.guest_memory)
                .unwrap_or_else(|_| {
                    // Fallback: construct a minimal E820 table even without a
                    // loaded kernel image.
                    let mut bp = crate::vmm::guest_memory::BootParams::new();
                    bp.finalize(&self.guest_memory);
                    bp
                });
            // Transmute the boot_params struct to raw bytes and write
            // to guest physical address BOOT_PARAMS_BASE.
            let bp_bytes: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    &boot_params as *const _ as *const u8,
                    core::mem::size_of_val(&boot_params),
                )
            };
            let _ = self.guest_memory.write_bytes(BOOT_PARAMS_BASE, bp_bytes);
        }

        Ok(())
    }

    /// Configure the VM with host_base=0 (test / no-Atlas mode).
    pub fn configure(&mut self, config: VmConfig) -> HvResult<()> {
        self.configure_with_allocation(config, 0, config.memory_size)
    }

    /// Set the Atlas allocation backing this VM's guest RAM.
    pub fn set_host_allocation(&mut self, allocation: Allocation) {
        self.host_allocation = Some(allocation);
    }

    /// Take the Atlas allocation out of this VM (for returning on delete).
    pub fn take_host_allocation(&mut self) -> Option<Allocation> {
        self.host_allocation.take()
    }

    pub fn start(&mut self) -> HvResult<()> {
        if self.state.load(Ordering::Acquire) != VmState::Created as u8 {
            return Err(HvError::LogicalFault);
        }

        self.state.store(VmState::Starting as u8, Ordering::Release);
        self.start_time.store(monotonic_ticks(), Ordering::Release);

        let eptp = unsafe { ept_for(self.id) }.eptp();
        let entry = self.kernel_loader.get_entry_point();

        // In non-test builds create a real Vmx context and attempt VMLAUNCH.
        // In test builds Vmx::new() is a no-op stub, so we skip the launch.
        #[cfg(not(test))]
        {
            use crate::vmm::guest_memory::{BOOT_STACK_BASE, BOOT_STACK_SIZE};
            let vmx = Vmx::new(eptp)?;
            vmx.set_guest_rip(entry)?;
            vmx.set_guest_rsp(BOOT_STACK_BASE + BOOT_STACK_SIZE)?;
            
            // Set VPID for the first vCPU (BSP)
            if let Some(vcpu) = self.vcpu_state.get_vcpu(0) {
                let vpid = vcpu.get_vpid();
                if vpid != 0 {
                    vmx.set_vpid(vpid)?;
                }
            }
            
            self.vmx = Some(vmx);
            // Install the active EPT so vm_exit_dispatch can map pages on
            // EPT violations without returning to Rust.
            unsafe {
                crate::vmm::vmx::set_active_ept(ept_for(self.id));
            }
            // VMLAUNCH transfers control to the guest — returns only on error.
            if let Some(ref v) = self.vmx {
                v.launch()?;
            }
        }

        // In tests, record entry and eptp without touching hardware.
        #[cfg(test)]
        {
            let _ = eptp;
            let _ = entry;
        }

        self.state.store(VmState::Running as u8, Ordering::Release);
        Ok(())
    }

    pub fn stop(&mut self) -> HvResult<()> {
        let current = self.state.load(Ordering::Acquire);
        if current != VmState::Running as u8 && current != VmState::Paused as u8 {
            return Err(HvError::LogicalFault);
        }

        self.state.store(VmState::Stopping as u8, Ordering::Release);

        self.state.store(VmState::Stopped as u8, Ordering::Release);

        Ok(())
    }

    pub fn pause(&mut self) -> HvResult<()> {
        if self.state.load(Ordering::Acquire) != VmState::Running as u8 {
            return Err(HvError::LogicalFault);
        }
        self.state.store(VmState::Paused as u8, Ordering::Release);
        Ok(())
    }

    pub fn resume(&mut self) -> HvResult<()> {
        if self.state.load(Ordering::Acquire) != VmState::Paused as u8 {
            return Err(HvError::LogicalFault);
        }
        self.state.store(VmState::Running as u8, Ordering::Release);
        Ok(())
    }

    pub fn get_state(&self) -> VmState {
        VmState::from_u8(self.state.load(Ordering::Acquire))
    }

    pub fn get_stats(&self) -> VmStats {
        let started = self.start_time.load(Ordering::Acquire);
        let now = monotonic_ticks();
        let uptime = if started == 0 {
            0
        } else {
            now.saturating_sub(started)
        };
        let (rx_packets, tx_packets, rx_bytes, tx_bytes, disk_reads, disk_writes) =
            self.virtio_mmio.stats();

        VmStats {
            vcpu_count: self.vcpu_state.get_count(),
            memory_size: self.guest_memory.total_usable_memory(),
            rx_packets,
            tx_packets,
            rx_bytes,
            tx_bytes,
            disk_reads,
            disk_writes,
            uptime,
        }
    }

    pub fn get_guest_memory(&self) -> &GuestMemory {
        &self.guest_memory
    }

    pub fn get_vcpu_state(&self) -> &VcpuState {
        &self.vcpu_state
    }

    pub fn get_config(&self) -> VmConfig {
        self.config
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

pub struct Hypervisor {
    capabilities: Capabilities,
    vms: [Option<VirtualMachine>; 16],
    vm_count: AtomicU32,
    max_vms: u32,
    /// Physical memory allocator for guest RAM backing.
    atlas: Atlas,
}

impl Hypervisor {
    pub fn new() -> Self {
        let caps = Self::probe_capabilities();

        Self {
            capabilities: caps,
            vms: [const { None }; 16],
            vm_count: AtomicU32::new(0),
            max_vms: 16,
            // Atlas::new() always succeeds (no hardware dependency).
            atlas: Atlas::new().expect("Atlas allocation"),
        }
    }

    fn probe_capabilities() -> Capabilities {
        let leaf1 = unsafe { core::arch::x86_64::__cpuid(1) };
        let leaf7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };

        let vmx = (leaf1.ecx & (1 << 5)) != 0;
        let x2apic = (leaf1.ecx & (1 << 21)) != 0;
        let tsc_deadline = (leaf1.ecx & (1 << 24)) != 0;
        let invariant_tsc =
            (unsafe { core::arch::x86_64::__cpuid_count(0x8000_0007, 0) }.edx & (1 << 8)) != 0;

        // Read IA32_VMX_PROCBASED_CTLS2 to check whether EPT is actually allowed.
        // Bit 1 of the allowed-1 settings (high 32 bits) indicates EPT support.
        let vmx_ctls2 = read_msr(IA32_VMX_PROCBASED_CTLS2);
        let ept_allowed1 = (vmx_ctls2 >> 32) as u32;
        let ept = vmx && ((ept_allowed1 & (1 << 1)) != 0);

        let _ = leaf7;
        Capabilities {
            vmx,
            ept,
            tsc_deadline,
            invariant_tsc,
            x2apic,
        }
    }

    pub fn get_capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub fn check_capabilities(&self) -> CapabilityDecision {
        evaluate_capabilities(self.capabilities)
    }

    pub fn create_vm(&mut self, config: VmConfig) -> HvResult<u32> {
        if self.vm_count.load(Ordering::Acquire) >= self.max_vms {
            return Err(HvError::LogicalFault);
        }

        let vm_id = self.vm_count.load(Ordering::Acquire);

        // Try to allocate guest RAM from Atlas.
        // If Atlas has free hugepages, use them; otherwise fall back
        // to host_base=0 (test mode / no physical memory).
        let mut vm = VirtualMachine::new(vm_id);
        if self.atlas.has_free() {
            let alloc = self.atlas.allocate_guest_region_sized(
                vm_id as u64,
                config.memory_size,
            )?;
            let host_base = alloc.base.0;
            let host_size = alloc.size;
            vm.set_host_allocation(alloc);
            vm.configure_with_allocation(config, host_base, host_size)?;
        } else {
            vm.configure(config)?;
        }

        self.vms[vm_id as usize] = Some(vm);
        self.vm_count.fetch_add(1, Ordering::Release);

        Ok(vm_id)
    }

    pub fn get_vm(&self, id: u32) -> Option<&VirtualMachine> {
        if id as usize >= 16 {
            return None;
        }
        self.vms[id as usize].as_ref()
    }

    pub fn get_vm_mut(&mut self, id: u32) -> Option<&mut VirtualMachine> {
        if id as usize >= 16 {
            return None;
        }
        self.vms[id as usize].as_mut()
    }

    pub fn delete_vm(&mut self, id: u32) -> HvResult<()> {
        if let Some(mut vm) = self.vms[id as usize].take() {
            if vm.get_state() == VmState::Running {
                // Put it back — can't delete a running VM.
                self.vms[id as usize] = Some(vm);
                return Err(HvError::LogicalFault);
            }
            // Free VPIDs for all vCPUs
            let vcpu_count = vm.get_vcpu_state().get_count();
            for i in 0..vcpu_count {
                if let Some(vcpu) = vm.get_vcpu_state().get_vcpu(i) {
                    vcpu.free_vpid();
                }
            }
            
            // Return the Atlas allocation so the memory can be reused.
            if let Some(alloc) = vm.take_host_allocation() {
                self.atlas.free_guest_region(alloc);
            }
            self.vm_count.fetch_sub(1, Ordering::Release);
            Ok(())
        } else {
            Err(HvError::LogicalFault)
        }
    }

    /// Reserve physical hugepages in the Atlas allocator.
    ///
    /// Called once during early boot before any VMs are created.
    /// `base`: host physical address of the first hugepage.
    /// `count`: number of 1 GiB hugepages to reserve.
    pub fn reserve_memory(&mut self, base: u64, count: usize) -> HvResult<()> {
        self.atlas.reserve_hugepages(base, count)
    }

    /// Return the Atlas allocator (for diagnostics / testing).
    pub fn atlas(&self) -> &Atlas {
        &self.atlas
    }

    pub fn get_vm_count(&self) -> u32 {
        self.vm_count.load(Ordering::Acquire)
    }
}

impl Default for Hypervisor {
    fn default() -> Self {
        Self::new()
    }
}
