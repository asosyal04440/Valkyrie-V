//! VirtIO-GPU device implementation for framebuffer display.
//!
//! Provides a simple 2D framebuffer device that can be used by guest OSes
//! like echOS for graphical output.

use crate::vmm::virtio_mmio::{VirtIODevice, VirtIoDeviceType, VIRTIO_DEVICE_GPU};
use crate::vmm::virtio_queue::{DescChainElem, SplitVirtqueue};
use crate::vmm::{HvError, HvResult};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, AtomicU16, Ordering};

/// VirtIO-GPU feature flags
pub const VIRTIO_GPU_F_VIRGL: u32 = 0;
pub const VIRTIO_GPU_F_EDID: u32 = 1;
pub const VIRTIO_GPU_F_RESOURCE_UUID: u32 = 2;
pub const VIRTIO_GPU_F_RESOURCE_BLOB: u32 = 3;
pub const VIRTIO_GPU_F_CONTEXT_INIT: u32 = 4;

/// VirtIO-GPU command types
pub mod cmd {
    pub const GET_DISPLAY_INFO: u32 = 0x0100;
    pub const RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const RESOURCE_UNREF: u32 = 0x0102;
    pub const SET_SCANOUT: u32 = 0x0103;
    pub const RESOURCE_FLUSH: u32 = 0x0104;
    pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const RESOURCE_DETACH_BACKING: u32 = 0x0107;
    pub const GET_CAPSET_INFO: u32 = 0x0108;
    pub const GET_CAPSET: u32 = 0x0109;
    pub const RESOURCE_CREATE_BLOB: u32 = 0x010a;
    pub const SET_SCANOUT_BLOB: u32 = 0x010b;
    pub const UPDATE_CURSOR: u32 = 0x0200;
    pub const MOVE_CURSOR: u32 = 0x0201;
}

/// VirtIO-GPU response types
pub mod resp {
    pub const NO_DATA: u32 = 0x1100;
    pub const DISPLAY_INFO: u32 = 0x1101;
    pub const CAPSET_INFO: u32 = 0x1108;
    pub const CAPSET: u32 = 0x1109;
}

/// VirtIO-GPU error codes
pub mod error {
    pub const OK: u32 = 0x0200;
    pub const UNSPEC: u32 = 0x0201;
    pub const OUT_OF_MEMORY: u32 = 0x0202;
    pub const INVALID_SCANOUT_ID: u32 = 0x0203;
    pub const INVALID_RESOURCE_ID: u32 = 0x0204;
    pub const INVALID_CONTEXT_ID: u32 = 0x0205;
    pub const INVALID_PARAMETER: u32 = 0x0206;
}

/// Default framebuffer dimensions
pub const DEFAULT_WIDTH: u32 = 1024;
pub const DEFAULT_HEIGHT: u32 = 768;
pub const DEFAULT_BPP: u32 = 32;

/// Maximum number of scanouts (displays)
pub const MAX_SCANOUTS: usize = 4;

/// Cursor types
pub mod cursor_type {
    pub const BITMAP: u32 = 0;
    pub const COLOR: u32 = 1;
}

/// Cursor command types
pub mod cursor_cmd {
    pub const SET: u32 = 0x0301;
    pub const MOVE: u32 = 0x0302;
    pub const UPDATE: u32 = 0x0303;
    pub const HIDE: u32 = 0x0304;
}

/// Cursor state
#[derive(Clone, Copy, Debug)]
pub struct CursorState {
    pub x: u32,
    pub y: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub visible: bool,
    pub resource_id: u32,
    pub cursor_type: u32,
}

impl CursorState {
    pub const fn new() -> Self {
        Self {
            x: 0,
            y: 0,
            hot_x: 0,
            hot_y: 0,
            visible: false,
            resource_id: 0,
            cursor_type: cursor_type::BITMAP,
        }
    }
}

/// Cursor command parameters
struct CursorParams {
    cursor_id: u32,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    cursor_type: u32,
}

/// VirtIO-GPU configuration
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtGpuConfig {
    pub events_read: u32,
    pub events_clear: u32,
    pub num_scanouts: u32,
    pub reserved: u32,
}

impl VirtGpuConfig {
    pub const fn new() -> Self {
        Self {
            events_read: 0,
            events_clear: 0,
            num_scanouts: 1,
            reserved: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// Display information for one scanout
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DisplayInfo {
    pub rect: Rect,
    pub enabled: u32,
    pub flags: u32,
}

impl DisplayInfo {
    pub const fn new(width: u32, height: u32) -> Self {
        Self {
            rect: Rect { x: 0, y: 0, width, height },
            enabled: 1,
            flags: 0,
        }
    }
}

/// Rectangle for display regions
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// GPU resource (2D surface)
#[derive(Clone, Copy, Debug)]
pub struct GpuResource {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub backing_addr: u64,
    pub backing_len: u32,
}

impl GpuResource {
    pub const fn new() -> Self {
        Self {
            id: 0,
            width: 0,
            height: 0,
            format: 0,
            backing_addr: 0,
            backing_len: 0,
        }
    }
}

/// Framebuffer state
pub struct Framebuffer {
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
    /// Framebuffer data (simplified - would be guest memory region in reality)
    pub data: [u8; DEFAULT_WIDTH as usize * DEFAULT_HEIGHT as usize * 4],
    /// Guest memory region base address (GPA) for direct framebuffer access
    pub guest_fb_addr: u64,
    /// Guest memory region size
    pub guest_fb_size: u64,
    /// Whether guest memory region is mapped
    pub guest_fb_mapped: bool,
    /// Host virtual address for mapped guest framebuffer
    pub host_fb_ptr: *mut u8,
}

/// SET_SCANOUT command parameters
struct SetScanoutParams {
    scanout_id: u32,
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

/// RESOURCE_CREATE_2D command parameters
struct Create2dParams {
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

/// RESOURCE_FLUSH command parameters
struct FlushParams {
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

/// TRANSFER_TO_HOST_2D command parameters
struct TransferParams {
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    offset: u64,
}

/// RESOURCE_ATTACH_BACKING command parameters
struct AttachBackingParams {
    resource_id: u32,
    nr_entries: u32,
    entries: [BackingEntry; 8],
}

/// Backing entry for resource
struct BackingEntry {
    addr: u64,
    length: u32,
    padding: u32,
}

impl Framebuffer {
    pub const fn new() -> Self {
        Self {
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            bpp: DEFAULT_BPP,
            pitch: DEFAULT_WIDTH * 4,
            data: [0u8; DEFAULT_WIDTH as usize * DEFAULT_HEIGHT as usize * 4],
            guest_fb_addr: 0,
            guest_fb_size: 0,
            guest_fb_mapped: false,
            host_fb_ptr: core::ptr::null_mut(),
        }
    }

    /// Map guest memory region for direct framebuffer access
    pub fn map_guest_region(&mut self, gpa: u64, size: u64, hva: *mut u8) {
        self.guest_fb_addr = gpa;
        self.guest_fb_size = size;
        self.host_fb_ptr = hva;
        self.guest_fb_mapped = !hva.is_null();
    }

    /// Unmap guest memory region
    pub fn unmap_guest_region(&mut self) {
        self.guest_fb_addr = 0;
        self.guest_fb_size = 0;
        self.host_fb_ptr = core::ptr::null_mut();
        self.guest_fb_mapped = false;
    }

    /// Check if guest memory region is mapped
    pub fn is_guest_mapped(&self) -> bool {
        self.guest_fb_mapped
    }

    /// Get guest framebuffer address
    pub fn guest_address(&self) -> u64 {
        self.guest_fb_addr
    }

    /// Read pixel from guest memory region
    pub unsafe fn read_pixel_guest(&self, x: u32, y: u32) -> u32 {
        if !self.guest_fb_mapped || self.host_fb_ptr.is_null() {
            return 0;
        }
        let offset = (y * self.pitch + x * 4) as usize;
        if offset + 4 > self.guest_fb_size as usize {
            return 0;
        }
        let ptr = self.host_fb_ptr.add(offset) as *const u32;
        ptr.read_volatile()
    }

    /// Write pixel to guest memory region
    pub unsafe fn write_pixel_guest(&self, x: u32, y: u32, color: u32) {
        if !self.guest_fb_mapped || self.host_fb_ptr.is_null() {
            return;
        }
        let offset = (y * self.pitch + x * 4) as usize;
        if offset + 4 > self.guest_fb_size as usize {
            return;
        }
        let ptr = self.host_fb_ptr.add(offset) as *mut u32;
        ptr.write_volatile(color);
    }

    /// Sync from guest memory to local data buffer
    pub fn sync_from_guest(&mut self) {
        if !self.guest_fb_mapped || self.host_fb_ptr.is_null() {
            return;
        }
        let copy_size = self.data.len().min(self.guest_fb_size as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.host_fb_ptr,
                self.data.as_mut_ptr(),
                copy_size,
            );
        }
    }

    /// Sync from local data buffer to guest memory
    pub fn sync_to_guest(&self) {
        if !self.guest_fb_mapped || self.host_fb_ptr.is_null() {
            return;
        }
        let copy_size = self.data.len().min(self.guest_fb_size as usize);
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data.as_ptr(),
                self.host_fb_ptr,
                copy_size,
            );
        }
    }

    /// Clear framebuffer with a color
    pub fn clear(&mut self, color: u32) {
        for pixel in self.data.chunks_exact_mut(4) {
            pixel.copy_from_slice(&color.to_le_bytes());
        }
    }

    /// Write pixel at (x, y)
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = (y * self.pitch + x * 4) as usize;
        if offset + 4 <= self.data.len() {
            self.data[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }

    /// Fill rectangle
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        for py in y..y.saturating_add(h).min(self.height) {
            for px in x..x.saturating_add(w).min(self.width) {
                self.put_pixel(px, py, color);
            }
        }
    }

    /// Copy from backing memory to framebuffer
    pub fn blit(&mut self, backing: &[u8], x: u32, y: u32, w: u32, h: u32, src_pitch: u32) {
        for row in 0..h {
            let src_y = row;
            let dst_y = y + row;
            if dst_y >= self.height {
                break;
            }
            
            let src_offset = (src_y * src_pitch) as usize;
            let dst_offset = (dst_y * self.pitch + x * 4) as usize;
            
            let copy_len = (w * 4) as usize;
            if src_offset + copy_len <= backing.len() && dst_offset + copy_len <= self.data.len() {
                self.data[dst_offset..dst_offset + copy_len]
                    .copy_from_slice(&backing[src_offset..src_offset + copy_len]);
            }
        }
    }
}

/// VirtIO-GPU device
pub struct VirtIoGpu {
    config: VirtGpuConfig,
    status: AtomicU8,
    features: AtomicU64,
    queue_ready: AtomicU8,
    /// Control queue (queue 0)
    control_vq: SplitVirtqueue,
    /// Cursor queue (queue 1)
    cursor_vq: SplitVirtqueue,
    /// Framebuffer
    framebuffer: Framebuffer,
    /// Resources
    resources: [GpuResource; 64],
    /// Display info for each scanout
    displays: [DisplayInfo; MAX_SCANOUTS],
    /// Cursor state
    cursor: CursorState,
    /// Statistics
    frames_rendered: AtomicU64,
    commands_processed: AtomicU64,
}

impl VirtIoGpu {
    pub fn new() -> Self {
        let mut displays = [DisplayInfo::new(0, 0); MAX_SCANOUTS];
        displays[0] = DisplayInfo::new(DEFAULT_WIDTH, DEFAULT_HEIGHT);

        Self {
            config: VirtGpuConfig::new(),
            status: AtomicU8::new(0),
            features: AtomicU64::new(0),
            queue_ready: AtomicU8::new(0),
            control_vq: SplitVirtqueue::new(),
            cursor_vq: SplitVirtqueue::new(),
            framebuffer: Framebuffer::new(),
            resources: [GpuResource::new(); 64],
            displays,
            cursor: CursorState::new(),
            frames_rendered: AtomicU64::new(0),
            commands_processed: AtomicU64::new(0),
        }
    }

    pub fn get_framebuffer(&self) -> &[u8] {
        &self.framebuffer.data
    }

    pub fn get_framebuffer_size(&self) -> usize {
        self.framebuffer.data.len()
    }

    pub fn get_display_info(&self) -> &[DisplayInfo; MAX_SCANOUTS] {
        &self.displays
    }

    /// Setup control virtqueue
    pub fn setup_control_queue(&mut self, size: u16, desc: u64, avail: u64, used: u64, guest_base: u64) {
        self.control_vq.setup(size, desc, avail, used, guest_base);
        self.queue_ready.store(1, Ordering::Release);
    }

    /// Process GPU commands from the control queue
    pub fn process_commands(&mut self) -> u32 {
        let mut processed = 0u32;

        while let Some(head) = self.control_vq.pop_avail() {
            let chain = self.control_vq.walk_chain(head);
            
            // Process command header (24 bytes)
            // struct virtio_gpu_ctrl_hdr {
            //     __le32 type;
            //     __le32 flags;
            //     __le64 fence_id;
            //     __le32 ctx_id;
            //     __le32 padding;
            // }
            
            // Read command type from guest memory via DMA
            let cmd_type = if chain.len() > 0 {
                let elem = &chain[0];
                if elem.len >= 4 {
                    // Use DMA engine to read from guest memory
                    // DMA engine would be passed from VirtIoMmio or hypervisor
                    // For now, we read from the mapped GPA
                    self.read_cmd_u32(elem.gpa)
                } else {
                    0
                }
            } else {
                0
            };
            
            // Process command based on type
            let response_len = match cmd_type {
                cmd::GET_DISPLAY_INFO => {
                    // Return display info response (80 bytes)
                    let resp = self.handle_get_display_info();
                    // Write response to guest memory via DMA
                    if chain.len() > 1 {
                        let resp_elem = &chain[1];
                        if resp_elem.flags & 0x1 != 0 { // Write descriptor
                            self.write_response(resp_elem.gpa, &resp);
                        }
                    }
                    80
                }
                cmd::SET_SCANOUT => {
                    // Set scanout configuration
                    // Read parameters from guest memory
                    if chain.len() > 0 {
                        let params = self.read_set_scanout_params(chain[0].gpa);
                        self.apply_scanout_config(params);
                    }
                    0
                }
                cmd::RESOURCE_CREATE_2D => {
                    // Create 2D resource
                    if chain.len() > 0 {
                        let params = self.read_create_2d_params(chain[0].gpa);
                        self.create_resource_2d(params);
                    }
                    0
                }
                cmd::RESOURCE_UNREF => {
                    // Unreference resource
                    if chain.len() > 0 {
                        let resource_id = self.read_resource_id(chain[0].gpa);
                        self.unref_resource(resource_id);
                    }
                    0
                }
                cmd::RESOURCE_FLUSH => {
                    // Flush resource to display
                    if chain.len() > 0 {
                        let params = self.read_flush_params(chain[0].gpa);
                        self.flush_resource(params);
                    }
                    self.frames_rendered.fetch_add(1, Ordering::Relaxed);
                    0
                }
                cmd::TRANSFER_TO_HOST_2D => {
                    // Transfer data to host
                    if chain.len() > 0 {
                        let params = self.read_transfer_params(chain[0].gpa);
                        self.transfer_to_host(params);
                    }
                    0
                }
                cmd::RESOURCE_ATTACH_BACKING => {
                    // Attach backing storage to resource
                    if chain.len() > 0 {
                        let params = self.read_attach_backing_params(chain[0].gpa);
                        self.attach_backing(params);
                    }
                    0
                }
                cmd::RESOURCE_DETACH_BACKING => {
                    // Detach backing storage
                    if chain.len() > 0 {
                        let resource_id = self.read_resource_id(chain[0].gpa);
                        self.detach_backing(resource_id);
                    }
                    0
                }
                _ => {
                    // Unknown command - ignore
                    0
                }
            };
            
            self.control_vq.push_used(head, response_len);
            self.commands_processed.fetch_add(1, Ordering::Relaxed);
            processed += 1;
        }

        processed
    }

    /// Read u32 from guest memory via DMA
    fn read_cmd_u32(&self, gpa: u64) -> u32 {
        // Use the global DMA engine from VirtioDirect
        crate::vmm::virtio_direct().dma.read_u32(gpa).unwrap_or(0)
    }

    /// Write response to guest memory via DMA
    fn write_response(&self, gpa: u64, data: &[u8]) {
        // Use the global DMA engine from VirtioDirect
        crate::vmm::virtio_direct().dma.write_bytes(gpa, data);
    }

    /// Read multiple bytes from guest memory via DMA
    fn read_bytes(&self, gpa: u64, buf: &mut [u8]) -> bool {
        crate::vmm::virtio_direct().dma.read_bytes(gpa, buf)
    }

    /// Read SET_SCANOUT parameters from guest memory
    fn read_set_scanout_params(&self, gpa: u64) -> SetScanoutParams {
        // struct virtio_gpu_set_scanout {
        //     hdr (24 bytes)
        //     scanout_id: u32 (offset 24)
        //     resource_id: u32 (offset 28)
        //     r: u32 (offset 32)
        //     x: u32 (offset 36)
        //     y: u32 (offset 40)
        //     width: u32 (offset 44)
        //     height: u32 (offset 48)
        // }
        SetScanoutParams {
            scanout_id: self.read_cmd_u32(gpa + 24),
            resource_id: self.read_cmd_u32(gpa + 28),
            x: self.read_cmd_u32(gpa + 36),
            y: self.read_cmd_u32(gpa + 40),
            width: self.read_cmd_u32(gpa + 44),
            height: self.read_cmd_u32(gpa + 48),
        }
    }

    /// Read RESOURCE_CREATE_2D parameters
    fn read_create_2d_params(&self, gpa: u64) -> Create2dParams {
        Create2dParams {
            resource_id: self.read_cmd_u32(gpa + 24),
            format: self.read_cmd_u32(gpa + 28),
            width: self.read_cmd_u32(gpa + 32),
            height: self.read_cmd_u32(gpa + 36),
        }
    }

    /// Read resource ID from command
    fn read_resource_id(&self, gpa: u64) -> u32 {
        self.read_cmd_u32(gpa + 24)
    }

    /// Read RESOURCE_FLUSH parameters
    fn read_flush_params(&self, gpa: u64) -> FlushParams {
        FlushParams {
            resource_id: self.read_cmd_u32(gpa + 24),
            x: self.read_cmd_u32(gpa + 28),
            y: self.read_cmd_u32(gpa + 32),
            width: self.read_cmd_u32(gpa + 36),
            height: self.read_cmd_u32(gpa + 40),
        }
    }

    /// Read TRANSFER_TO_HOST_2D parameters
    fn read_transfer_params(&self, gpa: u64) -> TransferParams {
        TransferParams {
            resource_id: self.read_cmd_u32(gpa + 24),
            x: self.read_cmd_u32(gpa + 28),
            y: self.read_cmd_u32(gpa + 32),
            width: self.read_cmd_u32(gpa + 36),
            height: self.read_cmd_u32(gpa + 40),
            offset: 0, // Would read from chain descriptors
        }
    }

    /// Read RESOURCE_ATTACH_BACKING parameters
    fn read_attach_backing_params(&self, gpa: u64) -> AttachBackingParams {
        AttachBackingParams {
            resource_id: self.read_cmd_u32(gpa + 24),
            nr_entries: self.read_cmd_u32(gpa + 28),
            entries: [], // Would read from chain descriptors
        }
    }

    /// Apply scanout configuration
    fn apply_scanout_config(&mut self, params: SetScanoutParams) {
        if params.scanout_id as usize >= MAX_SCANOUTS {
            return;
        }
        self.displays[params.scanout_id as usize].rect = Rect {
            x: params.x,
            y: params.y,
            width: params.width,
            height: params.height,
        };
    }

    /// Create 2D resource
    fn create_resource_2d(&mut self, params: Create2dParams) {
        // Find a free resource slot
        if params.resource_id == 0 || params.resource_id as usize >= self.resources.len() {
            return;
        }
        let idx = params.resource_id as usize;
        
        // Initialize the resource
        self.resources[idx] = GpuResource {
            id: params.resource_id,
            width: params.width,
            height: params.height,
            format: params.format,
            backing_addr: 0,
            backing_len: 0,
        };
    }

    /// Unreference resource
    fn unref_resource(&mut self, resource_id: u32) {
        if resource_id == 0 || resource_id as usize >= self.resources.len() {
            return;
        }
        let idx = resource_id as usize;
        
        // Clear the resource
        self.resources[idx] = GpuResource::new();
    }

    /// Flush resource to display
    fn flush_resource(&mut self, params: FlushParams) {
        if params.resource_id == 0 || params.resource_id as usize >= self.resources.len() {
            return;
        }
        let resource = &self.resources[params.resource_id as usize];
        
        // If resource has backing, copy to framebuffer
        if resource.backing_addr != 0 && resource.backing_len > 0 {
            // Read backing data from guest memory
            let backing_size = resource.backing_len as usize;
            let mut backing_data = [0u8; 4096]; // Stack buffer for small transfers
            
            // Copy in chunks if larger than buffer
            let mut src_offset = 0u64;
            let mut dst_y = params.y;
            
            while src_offset < backing_size as u64 {
                let chunk_size = backing_size.min(backing_data.len());
                let read_size = chunk_size.min((backing_size as u64 - src_offset) as usize);
                
                if self.read_bytes(resource.backing_addr + src_offset, &mut backing_data[..read_size]) {
                    // Blit to framebuffer
                    let src_pitch = resource.width * 4;
                    self.framebuffer.blit(
                        &backing_data[..read_size],
                        params.x,
                        dst_y,
                        params.width.min(resource.width),
                        params.height.min(resource.height),
                        src_pitch,
                    );
                }
                
                src_offset += chunk_size as u64;
                dst_y += params.height;
            }
        }
    }

    /// Transfer to host
    fn transfer_to_host(&mut self, params: TransferParams) {
        // Transfer data from guest to host - typically used for resource updates
        // This is a no-op for our simple implementation since we read directly
        // from guest memory during flush
        let _ = params;
    }

    /// Attach backing storage
    fn attach_backing(&mut self, params: AttachBackingParams) {
        if params.resource_id == 0 || params.resource_id as usize >= self.resources.len() {
            return;
        }
        let idx = params.resource_id as usize;
        
        // Store backing info from first entry
        if params.nr_entries > 0 {
            // Read backing entries from guest memory
            // For simplicity, use the first entry only
            let entry_gpa = params.resource_id as u64 * 0x1000 + 0x20; // Approximate
            let addr = self.read_cmd_u32(entry_gpa) as u64 | (self.read_cmd_u32(entry_gpa + 4) as u64) << 32;
            let len = self.read_cmd_u32(entry_gpa + 8);
            
            self.resources[idx].backing_addr = addr;
            self.resources[idx].backing_len = len;
        }
    }

    /// Detach backing storage
    fn detach_backing(&mut self, resource_id: u32) {
        if resource_id == 0 || resource_id as usize >= self.resources.len() {
            return;
        }
        let idx = resource_id as usize;
        
        // Clear backing info
        self.resources[idx].backing_addr = 0;
        self.resources[idx].backing_len = 0;
    }

    /// Process cursor queue commands
    pub fn process_cursor_commands(&mut self) -> u32 {
        let mut processed = 0u32;

        while let Some(head) = self.cursor_vq.pop_avail() {
            let chain = self.cursor_vq.walk_chain(head);
            
            let cmd_type = if chain.len() > 0 {
                let elem = &chain[0];
                if elem.len >= 4 {
                    self.read_cmd_u32(elem.gpa)
                } else {
                    0
                }
            } else {
                0
            };
            
            match cmd_type {
                cursor_cmd::SET => {
                    // Set cursor image
                    if chain.len() > 0 {
                        let params = self.read_cursor_params(chain[0].gpa);
                        self.set_cursor(params);
                    }
                }
                cursor_cmd::MOVE => {
                    // Move cursor position
                    if chain.len() > 0 {
                        let x = self.read_cmd_u32(chain[0].gpa + 24);
                        let y = self.read_cmd_u32(chain[0].gpa + 28);
                        self.move_cursor(x, y);
                    }
                }
                cursor_cmd::UPDATE => {
                    // Update cursor image data
                    if chain.len() > 0 {
                        let params = self.read_cursor_params(chain[0].gpa);
                        self.update_cursor(params);
                    }
                }
                cursor_cmd::HIDE => {
                    // Hide cursor
                    self.hide_cursor();
                }
                _ => {}
            }
            
            self.cursor_vq.push_used(head, 0);
            processed += 1;
        }

        processed
    }

    /// Read cursor command parameters
    fn read_cursor_params(&self, gpa: u64) -> CursorParams {
        CursorParams {
            cursor_id: self.read_cmd_u32(gpa + 24),
            resource_id: self.read_cmd_u32(gpa + 28),
            hot_x: self.read_cmd_u32(gpa + 32),
            hot_y: self.read_cmd_u32(gpa + 36),
            x: self.read_cmd_u32(gpa + 40),
            y: self.read_cmd_u32(gpa + 44),
            width: self.read_cmd_u32(gpa + 48),
            height: self.read_cmd_u32(gpa + 52),
            cursor_type: self.read_cmd_u32(gpa + 56),
        }
    }

    /// Set cursor from resource
    fn set_cursor(&mut self, params: CursorParams) {
        self.cursor.resource_id = params.resource_id;
        self.cursor.hot_x = params.hot_x;
        self.cursor.hot_y = params.hot_y;
        self.cursor.visible = true;
        self.cursor.cursor_type = params.cursor_type;
    }

    /// Move cursor to new position
    fn move_cursor(&mut self, x: u32, y: u32) {
        self.cursor.x = x;
        self.cursor.y = y;
    }

    /// Update cursor image data
    fn update_cursor(&mut self, params: CursorParams) {
        self.cursor.resource_id = params.resource_id;
        self.cursor.hot_x = params.hot_x;
        self.cursor.hot_y = params.hot_y;
    }

    /// Hide cursor
    fn hide_cursor(&mut self) {
        self.cursor.visible = false;
    }

    /// Get cursor state
    pub fn get_cursor(&self) -> &CursorState {
        &self.cursor
    }

    /// Handle GET_DISPLAY_INFO command
    fn handle_get_display_info(&self) -> [u8; 80] {
        let mut resp = [0u8; 80];
        
        // Response header
        resp[0..4].copy_from_slice(&resp::DISPLAY_INFO.to_le_bytes());
        resp[4..8].copy_from_slice(&error::OK.to_le_bytes());
        
        // Number of scanouts
        resp[8..12].copy_from_slice(&self.config.num_scanouts.to_le_bytes());
        
        // Display info for each scanout
        for (i, display) in self.displays.iter().enumerate().take(MAX_SCANOUTS) {
            let offset = 12 + i * 16;
            resp[offset..offset + 4].copy_from_slice(&display.rect.x.to_le_bytes());
            resp[offset + 4..offset + 8].copy_from_slice(&display.rect.y.to_le_bytes());
            resp[offset + 8..offset + 12].copy_from_slice(&display.rect.width.to_le_bytes());
            resp[offset + 12..offset + 16].copy_from_slice(&display.rect.height.to_le_bytes());
        }

        resp
    }

    pub fn get_stats(&self) -> (u64, u64) {
        (
            self.frames_rendered.load(Ordering::Acquire),
            self.commands_processed.load(Ordering::Acquire),
        )
    }
}

impl Default for VirtIoGpu {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtIODevice for VirtIoGpu {
    fn device_type(&self) -> VirtIoDeviceType {
        VirtIoDeviceType::Gpu
    }

    fn device_id(&self) -> u32 {
        VIRTIO_DEVICE_GPU
    }

    fn vendor_id(&self) -> u32 {
        0x1AF4
    }

    fn get_features(&self) -> u64 {
        // Basic features only
        (1 << VIRTIO_GPU_F_EDID)
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.features.store(features, Ordering::Release);
        Ok(())
    }

    fn get_status(&self) -> u32 {
        self.status.load(Ordering::Acquire) as u32
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.status.store(status as u8, Ordering::Release);
        Ok(())
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        let config_bytes = self.config.to_bytes();
        let start = offset as usize;
        let end = (start + data.len()).min(16);

        if start >= 16 {
            return Err(HvError::LogicalFault);
        }

        data[..(end - start)].copy_from_slice(&config_bytes[start..end]);
        Ok(())
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        // Events_clear is writable at offset 4
        if offset == 4 && data.len() >= 4 {
            let clear_flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            self.config.events_read &= !clear_flags;
        }
        Ok(())
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        if self.queue_ready.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }

        match queue {
            0 => {
                // Control queue
                self.process_commands();
            }
            1 => {
                // Cursor queue
                self.process_cursor_commands();
            }
            _ => {}
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_device_creation() {
        let gpu = VirtIoGpu::new();
        assert_eq!(gpu.device_id(), VIRTIO_DEVICE_GPU);
        assert_eq!(gpu.get_features() & (1 << VIRTIO_GPU_F_EDID), 1 << VIRTIO_GPU_F_EDID);
    }

    #[test]
    fn framebuffer_clear() {
        let mut gpu = VirtIoGpu::new();
        gpu.framebuffer.clear(0xFF0000FF); // Blue
        // Check first pixel is blue
        assert_eq!(gpu.framebuffer.data[0], 0xFF);
        assert_eq!(gpu.framebuffer.data[1], 0x00);
        assert_eq!(gpu.framebuffer.data[2], 0x00);
        assert_eq!(gpu.framebuffer.data[3], 0xFF);
    }

    #[test]
    fn display_info() {
        let gpu = VirtIoGpu::new();
        let displays = gpu.get_display_info();
        assert_eq!(displays[0].rect.width, DEFAULT_WIDTH);
        assert_eq!(displays[0].rect.height, DEFAULT_HEIGHT);
        assert_eq!(displays[0].enabled, 1);
    }
}
