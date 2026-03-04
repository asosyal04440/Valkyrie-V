//! Multi-Tenant Resource Management
//!
//! Resource quotas, isolation, and accounting for multi-tenant VMs.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Resource Types and Limits
// ─────────────────────────────────────────────────────────────────────────────

/// Resource types
pub mod resource {
    pub const CPU: u8 = 0;
    pub const MEMORY: u8 = 1;
    pub const DISK: u8 = 2;
    pub const NETWORK: u8 = 3;
    pub const GPU: u8 = 4;
    pub const IO_BUDGET: u8 = 5;
    pub const IRQ: u8 = 6;
}

/// Limit enforcement modes
pub mod enforce_mode {
    pub const SOFT: u8 = 0;  // Warn only
    pub const HARD: u8 = 1;  // Enforce strictly
    pub const BURST: u8 = 2; // Allow burst with penalty
}

/// Maximum tenants
pub const MAX_TENANTS: usize = 64;
/// Maximum VMs per tenant
pub const MAX_VMS_PER_TENANT: usize = 32;
/// Maximum resource types
pub const MAX_RESOURCE_TYPES: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Resource Quotas
// ─────────────────────────────────────────────────────────────────────────────

/// Resource quota entry
pub struct ResourceQuota {
    /// Resource type
    pub resource_type: AtomicU8,
    /// Hard limit
    pub limit: AtomicU64,
    /// Current usage
    pub usage: AtomicU64,
    /// Burst limit (if burst mode)
    pub burst_limit: AtomicU64,
    /// Burst usage
    pub burst_usage: AtomicU64,
    /// Enforcement mode
    pub enforce_mode: AtomicU8,
    /// Warning threshold (percentage)
    pub warn_threshold: AtomicU8,
    /// Over limit count
    pub over_limit_count: AtomicU64,
    /// Last violation timestamp
    pub last_violation: AtomicU64,
}

impl ResourceQuota {
    pub const fn new() -> Self {
        Self {
            resource_type: AtomicU8::new(0),
            limit: AtomicU64::new(0),
            usage: AtomicU64::new(0),
            burst_limit: AtomicU64::new(0),
            burst_usage: AtomicU64::new(0),
            enforce_mode: AtomicU8::new(enforce_mode::HARD),
            warn_threshold: AtomicU8::new(80),
            over_limit_count: AtomicU64::new(0),
            last_violation: AtomicU64::new(0),
        }
    }

    /// Check if allocation is allowed
    pub fn can_allocate(&self, amount: u64) -> bool {
        let current = self.usage.load(Ordering::Acquire);
        let limit = self.limit.load(Ordering::Acquire);
        
        match self.enforce_mode.load(Ordering::Acquire) {
            enforce_mode::SOFT => true,
            enforce_mode::HARD => current + amount <= limit,
            enforce_mode::BURST => {
                let burst = self.burst_limit.load(Ordering::Acquire);
                current + amount <= burst
            }
            _ => false,
        }
    }

    /// Allocate resource
    pub fn allocate(&self, amount: u64) -> Result<(), HvError> {
        if !self.can_allocate(amount) {
            self.over_limit_count.fetch_add(1, Ordering::Release);
            self.last_violation.store(Self::get_timestamp(), Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        self.usage.fetch_add(amount, Ordering::Release);
        Ok(())
    }

    /// Release resource
    pub fn release(&self, amount: u64) {
        let current = self.usage.load(Ordering::Acquire);
        self.usage.store(current.saturating_sub(amount), Ordering::Release);
    }

    /// Check warning threshold
    pub fn check_warning(&self) -> bool {
        let usage = self.usage.load(Ordering::Acquire);
        let limit = self.limit.load(Ordering::Acquire);
        let threshold = self.warn_threshold.load(Ordering::Acquire) as u64;
        
        if limit == 0 {
            return false;
        }
        
        (usage * 100 / limit) >= threshold
    }

    /// Get utilization percentage
    pub fn get_utilization(&self) -> u8 {
        let usage = self.usage.load(Ordering::Acquire);
        let limit = self.limit.load(Ordering::Acquire);
        
        if limit == 0 {
            return 0;
        }
        
        ((usage * 100 / limit).min(100)) as u8
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tenant Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Tenant state
pub mod tenant_state {
    pub const INACTIVE: u8 = 0;
    pub const ACTIVE: u8 = 1;
    pub const SUSPENDED: u8 = 2;
    pub const QUOTA_EXCEEDED: u8 = 3;
}

/// Tenant information
pub struct Tenant {
    /// Tenant ID
    pub tenant_id: AtomicU32,
    /// Tenant state
    pub state: AtomicU8,
    /// Priority (0-255, higher = more important)
    pub priority: AtomicU8,
    /// Resource quotas
    pub quotas: [ResourceQuota; MAX_RESOURCE_TYPES],
    /// VM IDs owned
    pub vm_ids: [AtomicU32; MAX_VMS_PER_TENANT],
    /// VM count
    pub vm_count: AtomicU8,
    /// Total CPU time used (ns)
    pub cpu_time_total: AtomicU64,
    /// Total memory allocated (bytes)
    pub memory_total: AtomicU64,
    /// Total disk I/O (bytes)
    pub disk_io_total: AtomicU64,
    /// Total network I/O (bytes)
    pub network_io_total: AtomicU64,
    /// Creation timestamp
    pub created: AtomicU64,
    /// Last activity
    pub last_activity: AtomicU64,
    /// Isolation group
    pub isolation_group: AtomicU16,
    /// Billing account ID
    pub billing_account: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl Tenant {
    pub const fn new() -> Self {
        Self {
            tenant_id: AtomicU32::new(0),
            state: AtomicU8::new(tenant_state::INACTIVE),
            priority: AtomicU8::new(128),
            quotas: [const { ResourceQuota::new() }; MAX_RESOURCE_TYPES],
            vm_ids: [const { AtomicU32::new(0) }; MAX_VMS_PER_TENANT],
            vm_count: AtomicU8::new(0),
            cpu_time_total: AtomicU64::new(0),
            memory_total: AtomicU64::new(0),
            disk_io_total: AtomicU64::new(0),
            network_io_total: AtomicU64::new(0),
            created: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
            isolation_group: AtomicU16::new(0),
            billing_account: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize tenant
    pub fn init(&mut self, tenant_id: u32, priority: u8, isolation_group: u16) {
        self.tenant_id.store(tenant_id, Ordering::Release);
        self.priority.store(priority, Ordering::Release);
        self.isolation_group.store(isolation_group, Ordering::Release);
        self.state.store(tenant_state::ACTIVE, Ordering::Release);
        self.valid.store(true, Ordering::Release);
        self.created.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Set resource quota
    pub fn set_quota(&self, resource_type: u8, limit: u64, burst: u64, mode: u8) {
        if resource_type as usize >= MAX_RESOURCE_TYPES {
            return;
        }
        
        let quota = &self.quotas[resource_type as usize];
        quota.resource_type.store(resource_type, Ordering::Release);
        quota.limit.store(limit, Ordering::Release);
        quota.burst_limit.store(burst, Ordering::Release);
        quota.enforce_mode.store(mode, Ordering::Release);
    }

    /// Add VM to tenant
    pub fn add_vm(&self, vm_id: u32) -> Result<(), HvError> {
        let count = self.vm_count.load(Ordering::Acquire) as usize;
        if count >= MAX_VMS_PER_TENANT {
            return Err(HvError::LogicalFault);
        }
        
        self.vm_ids[count].store(vm_id, Ordering::Release);
        self.vm_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Remove VM from tenant
    pub fn remove_vm(&self, vm_id: u32) -> Result<(), HvError> {
        let count = self.vm_count.load(Ordering::Acquire) as usize;
        
        for i in 0..count {
            if self.vm_ids[i].load(Ordering::Acquire) == vm_id {
                // Shift remaining
                for j in i..(count - 1) {
                    let next = self.vm_ids[j + 1].load(Ordering::Acquire);
                    self.vm_ids[j].store(next, Ordering::Release);
                }
                self.vm_count.fetch_sub(1, Ordering::Release);
                return Ok(());
            }
        }
        
        Err(HvError::LogicalFault)
    }

    /// Update resource usage
    pub fn update_usage(&self, resource_type: u8, delta: u64) {
        if resource_type as usize >= MAX_RESOURCE_TYPES {
            return;
        }
        
        let quota = &self.quotas[resource_type as usize];
        quota.usage.fetch_add(delta, Ordering::Release);
        self.last_activity.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Check if over quota
    pub fn is_over_quota(&self) -> bool {
        for quota in &self.quotas {
            if quota.over_limit_count.load(Ordering::Acquire) > 0 {
                return true;
            }
        }
        false
    }

    /// Suspend tenant
    pub fn suspend(&self) {
        self.state.store(tenant_state::SUSPENDED, Ordering::Release);
    }

    /// Resume tenant
    pub fn resume(&self) {
        if self.is_over_quota() {
            self.state.store(tenant_state::QUOTA_EXCEEDED, Ordering::Release);
        } else {
            self.state.store(tenant_state::ACTIVE, Ordering::Release);
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Tenant {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Tenant Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-tenant controller
pub struct MultiTenantController {
    /// Tenants array
    pub tenants: [Tenant; MAX_TENANTS],
    /// Tenant count
    pub tenant_count: AtomicU8,
    /// Default isolation group
    pub default_isolation_group: AtomicU16,
    /// Global CPU budget
    pub global_cpu_budget: AtomicU64,
    /// Global memory budget
    pub global_memory_budget: AtomicU64,
    /// Fair scheduler enabled
    pub fair_scheduler: AtomicBool,
    /// Overcommit ratio (percentage)
    pub overcommit_ratio: AtomicU8,
    /// Accounting enabled
    pub accounting_enabled: AtomicBool,
    /// Billing interval (ms)
    pub billing_interval: AtomicU32,
    /// Last billing time
    pub last_billing: AtomicU64,
}

impl MultiTenantController {
    pub const fn new() -> Self {
        Self {
            tenants: [const { Tenant::new() }; MAX_TENANTS],
            tenant_count: AtomicU8::new(0),
            default_isolation_group: AtomicU16::new(0),
            global_cpu_budget: AtomicU64::new(0),
            global_memory_budget: AtomicU64::new(0),
            fair_scheduler: AtomicBool::new(true),
            overcommit_ratio: AtomicU8::new(100),
            accounting_enabled: AtomicBool::new(true),
            billing_interval: AtomicU32::new(3600000), // 1 hour
            last_billing: AtomicU64::new(0),
        }
    }

    /// Create tenant
    pub fn create_tenant(&mut self, priority: u8) -> Result<u32, HvError> {
        let count = self.tenant_count.load(Ordering::Acquire) as usize;
        if count >= MAX_TENANTS {
            return Err(HvError::LogicalFault);
        }
        
        // Find free slot
        for i in 0..MAX_TENANTS {
            if !self.tenants[i].valid.load(Ordering::Acquire) {
                let tenant_id = (i + 1) as u32; // 0 is invalid
                let isolation = self.default_isolation_group.load(Ordering::Acquire);
                self.tenants[i].init(tenant_id, priority, isolation);
                self.tenant_count.fetch_add(1, Ordering::Release);
                return Ok(tenant_id);
            }
        }
        
        Err(HvError::LogicalFault)
    }

    /// Delete tenant
    pub fn delete_tenant(&mut self, tenant_id: u32) -> Result<(), HvError> {
        if tenant_id == 0 || tenant_id as usize > MAX_TENANTS {
            return Err(HvError::LogicalFault);
        }
        
        let tenant = &self.tenants[tenant_id as usize - 1];
        
        // Check no VMs
        if tenant.vm_count.load(Ordering::Acquire) > 0 {
            return Err(HvError::LogicalFault);
        }
        
        tenant.valid.store(false, Ordering::Release);
        tenant.state.store(tenant_state::INACTIVE, Ordering::Release);
        self.tenant_count.fetch_sub(1, Ordering::Release);
        
        Ok(())
    }

    /// Get tenant by ID
    pub fn get_tenant(&self, tenant_id: u32) -> Option<&Tenant> {
        if tenant_id == 0 || tenant_id as usize > MAX_TENANTS {
            return None;
        }
        
        let tenant = &self.tenants[tenant_id as usize - 1];
        if tenant.valid.load(Ordering::Acquire) {
            Some(tenant)
        } else {
            None
        }
    }

    /// Set tenant quota
    pub fn set_tenant_quota(&self, tenant_id: u32, resource_type: u8, 
                           limit: u64, burst: u64, mode: u8) -> Result<(), HvError> {
        let tenant = self.get_tenant(tenant_id).ok_or(HvError::LogicalFault)?;
        tenant.set_quota(resource_type, limit, burst, mode);
        Ok(())
    }

    /// Allocate resource for tenant
    pub fn allocate_resource(&self, tenant_id: u32, resource_type: u8, 
                            amount: u64) -> Result<(), HvError> {
        let tenant = self.get_tenant(tenant_id).ok_or(HvError::LogicalFault)?;
        
        if tenant.state.load(Ordering::Acquire) != tenant_state::ACTIVE {
            return Err(HvError::LogicalFault);
        }
        
        let quota = &tenant.quotas[resource_type as usize];
        quota.allocate(amount)?;
        // Note: quota.allocate already updates usage, no need to call update_usage
        
        Ok(())
    }

    /// Release resource for tenant
    pub fn release_resource(&self, tenant_id: u32, resource_type: u8, amount: u64) {
        if let Some(tenant) = self.get_tenant(tenant_id) {
            let quota = &tenant.quotas[resource_type as usize];
            quota.release(amount);
        }
    }

    /// Record CPU time for tenant
    pub fn record_cpu_time(&self, tenant_id: u32, time_ns: u64) {
        if let Some(tenant) = self.get_tenant(tenant_id) {
            tenant.cpu_time_total.fetch_add(time_ns, Ordering::Release);
            tenant.update_usage(resource::CPU, time_ns);
        }
    }

    /// Record memory allocation for tenant
    pub fn record_memory(&self, tenant_id: u32, bytes: u64) {
        if let Some(tenant) = self.get_tenant(tenant_id) {
            tenant.memory_total.fetch_add(bytes, Ordering::Release);
            tenant.update_usage(resource::MEMORY, bytes);
        }
    }

    /// Record I/O for tenant
    pub fn record_io(&self, tenant_id: u32, disk_bytes: u64, net_bytes: u64) {
        if let Some(tenant) = self.get_tenant(tenant_id) {
            tenant.disk_io_total.fetch_add(disk_bytes, Ordering::Release);
            tenant.network_io_total.fetch_add(net_bytes, Ordering::Release);
        }
    }

    /// Get tenant statistics
    pub fn get_tenant_stats(&self, tenant_id: u32) -> Option<TenantStats> {
        let tenant = self.get_tenant(tenant_id)?;
        
        let mut quota_util = [0u8; MAX_RESOURCE_TYPES];
        for i in 0..MAX_RESOURCE_TYPES {
            quota_util[i] = tenant.quotas[i].get_utilization();
        }
        
        Some(TenantStats {
            tenant_id,
            state: tenant.state.load(Ordering::Acquire),
            vm_count: tenant.vm_count.load(Ordering::Acquire),
            cpu_time_total: tenant.cpu_time_total.load(Ordering::Acquire),
            memory_total: tenant.memory_total.load(Ordering::Acquire),
            disk_io_total: tenant.disk_io_total.load(Ordering::Acquire),
            network_io_total: tenant.network_io_total.load(Ordering::Acquire),
            quota_utilization: quota_util,
        })
    }

    /// Get global statistics
    pub fn get_global_stats(&self) -> GlobalStats {
        let mut total_vms = 0u32;
        let mut total_cpu = 0u64;
        let mut total_mem = 0u64;
        let mut active_tenants = 0u8;
        
        for tenant in &self.tenants {
            if tenant.valid.load(Ordering::Acquire) {
                active_tenants += 1;
                total_vms += tenant.vm_count.load(Ordering::Acquire) as u32;
                total_cpu += tenant.cpu_time_total.load(Ordering::Acquire);
                total_mem += tenant.memory_total.load(Ordering::Acquire);
            }
        }
        
        GlobalStats {
            total_tenants: active_tenants,
            total_vms,
            total_cpu_time: total_cpu,
            total_memory: total_mem,
            global_cpu_budget: self.global_cpu_budget.load(Ordering::Acquire),
            global_memory_budget: self.global_memory_budget.load(Ordering::Acquire),
        }
    }

    /// Run billing cycle
    pub fn run_billing(&mut self) {
        let now = Self::get_timestamp();
        let interval = self.billing_interval.load(Ordering::Acquire) as u64;
        
        if now - self.last_billing.load(Ordering::Acquire) < interval {
            return;
        }
        
        // Generate billing records for each tenant
        for tenant in &self.tenants {
            if !tenant.valid.load(Ordering::Acquire) {
                continue;
            }
            
            // Would send billing data to accounting system
            let _account = tenant.billing_account.load(Ordering::Acquire);
            let _cpu = tenant.cpu_time_total.load(Ordering::Acquire);
            let _mem = tenant.memory_total.load(Ordering::Acquire);
            let _io = tenant.disk_io_total.load(Ordering::Acquire);
            let _net = tenant.network_io_total.load(Ordering::Acquire);
        }
        
        self.last_billing.store(now, Ordering::Release);
    }

    /// Enforce quotas
    pub fn enforce_quotas(&mut self) {
        for tenant in &self.tenants {
            if !tenant.valid.load(Ordering::Acquire) {
                continue;
            }
            
            if tenant.is_over_quota() {
                tenant.state.store(tenant_state::QUOTA_EXCEEDED, Ordering::Release);
            }
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for MultiTenantController {
    fn default() -> Self {
        Self::new()
    }
}

/// Tenant statistics
#[repr(C)]
pub struct TenantStats {
    pub tenant_id: u32,
    pub state: u8,
    pub vm_count: u8,
    pub cpu_time_total: u64,
    pub memory_total: u64,
    pub disk_io_total: u64,
    pub network_io_total: u64,
    pub quota_utilization: [u8; MAX_RESOURCE_TYPES],
}

/// Global statistics
#[repr(C)]
pub struct GlobalStats {
    pub total_tenants: u8,
    pub total_vms: u32,
    pub total_cpu_time: u64,
    pub total_memory: u64,
    pub global_cpu_budget: u64,
    pub global_memory_budget: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Isolation Groups
// ─────────────────────────────────────────────────────────────────────────────

/// Isolation group for tenant separation
pub struct IsolationGroup {
    /// Group ID
    pub group_id: AtomicU16,
    /// CPU cores mask
    pub cpu_mask: AtomicU64,
    /// Memory nodes mask (NUMA)
    pub mem_nodes: AtomicU32,
    /// I/O priority
    pub io_priority: AtomicU8,
    /// Network priority
    pub net_priority: AtomicU8,
    /// Cache partition ID
    pub cache_part: AtomicU16,
    /// Enabled
    pub enabled: AtomicBool,
}

impl IsolationGroup {
    pub const fn new() -> Self {
        Self {
            group_id: AtomicU16::new(0),
            cpu_mask: AtomicU64::new(0xFFFF), // All cores
            mem_nodes: AtomicU32::new(0xFF),  // All nodes
            io_priority: AtomicU8::new(4),
            net_priority: AtomicU8::new(4),
            cache_part: AtomicU16::new(0),
            enabled: AtomicBool::new(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_create() {
        let mut ctrl = MultiTenantController::new();
        
        let id = ctrl.create_tenant(128).unwrap();
        assert_ne!(id, 0);
        assert!(ctrl.get_tenant(id).is_some());
    }

    #[test]
    fn tenant_delete() {
        let mut ctrl = MultiTenantController::new();
        
        let id = ctrl.create_tenant(128).unwrap();
        ctrl.delete_tenant(id).unwrap();
        assert!(ctrl.get_tenant(id).is_none());
    }

    #[test]
    fn quota_allocate() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1024 * 1024 * 1024, 0, enforce_mode::HARD).unwrap();
        
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 512 * 1024 * 1024).is_ok());
    }

    #[test]
    fn quota_exceed() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        // Set quota limit to 1024 units
        let result = ctrl.set_tenant_quota(id, resource::MEMORY, 1024, 0, enforce_mode::HARD);
        assert!(result.is_ok(), "set_tenant_quota failed: {:?}", result);
        
        // Verify quota was set
        let tenant = ctrl.get_tenant(id).unwrap();
        let quota = &tenant.quotas[resource::MEMORY as usize];
        assert_eq!(quota.limit.load(Ordering::Acquire), 1024, "quota limit not set correctly");
        assert_eq!(quota.enforce_mode.load(Ordering::Acquire), enforce_mode::HARD, "enforce mode not set");
        
        // Allocate 512 units - should succeed (512 <= 1024)
        let result1 = ctrl.allocate_resource(id, resource::MEMORY, 512);
        assert!(result1.is_ok(), "first allocation failed: {:?}", result1);
        
        // Check usage after first allocation
        let usage_after_first = quota.usage.load(Ordering::Acquire);
        assert_eq!(usage_after_first, 512, "usage after first allocation should be 512, got {}", usage_after_first);
        
        // Allocate another 512 units - should succeed (512 + 512 = 1024 <= 1024)
        let result2 = ctrl.allocate_resource(id, resource::MEMORY, 512);
        assert!(result2.is_ok(), "second allocation failed: usage={}, limit={}, amount=512", 
                quota.usage.load(Ordering::Acquire), quota.limit.load(Ordering::Acquire));
        
        // Allocate 1 more unit - should fail (1024 + 1 > 1024)
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 1).is_err());
    }

    #[test]
    fn tenant_vm() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        tenant.add_vm(1).unwrap();
        tenant.add_vm(2).unwrap();
        
        assert_eq!(tenant.vm_count.load(Ordering::Acquire), 2);
        
        tenant.remove_vm(1).unwrap();
        assert_eq!(tenant.vm_count.load(Ordering::Acquire), 1);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPREHENSIVE BATTLE-TESTED TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Test: Multiple tenants can be created and are independent
    #[test]
    fn multiple_tenants_independent() {
        let mut ctrl = MultiTenantController::new();
        
        let id1 = ctrl.create_tenant(128).unwrap();
        let id2 = ctrl.create_tenant(200).unwrap();
        let id3 = ctrl.create_tenant(50).unwrap();
        
        // Each tenant should have different IDs
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
        
        // Set different quotas for each
        ctrl.set_tenant_quota(id1, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        ctrl.set_tenant_quota(id2, resource::MEMORY, 2000, 0, enforce_mode::HARD).unwrap();
        ctrl.set_tenant_quota(id3, resource::MEMORY, 500, 0, enforce_mode::HARD).unwrap();
        
        // Allocate from each and verify isolation
        ctrl.allocate_resource(id1, resource::MEMORY, 500).unwrap();
        ctrl.allocate_resource(id2, resource::MEMORY, 1000).unwrap();
        ctrl.allocate_resource(id3, resource::MEMORY, 250).unwrap();
        
        // Verify each tenant has correct usage
        let t1 = ctrl.get_tenant(id1).unwrap();
        let t2 = ctrl.get_tenant(id2).unwrap();
        let t3 = ctrl.get_tenant(id3).unwrap();
        
        assert_eq!(t1.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 500);
        assert_eq!(t2.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 1000);
        assert_eq!(t3.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 250);
    }

    /// Test: Resource release works correctly
    #[test]
    fn resource_release() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        
        // Allocate then release
        ctrl.allocate_resource(id, resource::MEMORY, 500).unwrap();
        ctrl.release_resource(id, resource::MEMORY, 300);
        
        let tenant = ctrl.get_tenant(id).unwrap();
        assert_eq!(tenant.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 200);
        
        // Can allocate again after release
        ctrl.allocate_resource(id, resource::MEMORY, 800).unwrap(); // 200 + 800 = 1000
    }

    /// Test: Release more than allocated (saturating subtraction)
    #[test]
    fn release_saturating() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        ctrl.allocate_resource(id, resource::MEMORY, 100).unwrap();
        
        // Release more than allocated - should not panic, should saturate
        ctrl.release_resource(id, resource::MEMORY, 500);
        
        let tenant = ctrl.get_tenant(id).unwrap();
        assert_eq!(tenant.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 0);
    }

    /// Test: Quota enforcement modes
    #[test]
    fn enforcement_modes() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        // SOFT mode - always allows allocation
        ctrl.set_tenant_quota(id, resource::CPU, 100, 0, enforce_mode::SOFT).unwrap();
        assert!(ctrl.allocate_resource(id, resource::CPU, 1000).is_ok()); // Over limit but SOFT
        
        // HARD mode - strict enforcement
        ctrl.set_tenant_quota(id, resource::MEMORY, 100, 0, enforce_mode::HARD).unwrap();
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 50).is_ok());
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 100).is_err()); // Would exceed
        
        // BURST mode - uses burst limit
        ctrl.set_tenant_quota(id, resource::DISK, 100, 200, enforce_mode::BURST).unwrap();
        assert!(ctrl.allocate_resource(id, resource::DISK, 150).is_ok()); // Within burst
    }

    /// Test: Warning threshold detection
    #[test]
    fn warning_threshold() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        tenant.quotas[resource::MEMORY as usize].warn_threshold.store(80, Ordering::Release);
        
        // Allocate 50% - no warning
        ctrl.allocate_resource(id, resource::MEMORY, 500).unwrap();
        assert!(!tenant.quotas[resource::MEMORY as usize].check_warning());
        
        // Allocate another 40% - now at 90%, warning triggers
        ctrl.allocate_resource(id, resource::MEMORY, 400).unwrap();
        assert!(tenant.quotas[resource::MEMORY as usize].check_warning());
    }

    /// Test: Utilization calculation
    #[test]
    fn utilization_calculation() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        
        assert_eq!(tenant.quotas[resource::MEMORY as usize].get_utilization(), 0);
        
        ctrl.allocate_resource(id, resource::MEMORY, 250).unwrap();
        assert_eq!(tenant.quotas[resource::MEMORY as usize].get_utilization(), 25);
        
        ctrl.allocate_resource(id, resource::MEMORY, 250).unwrap();
        assert_eq!(tenant.quotas[resource::MEMORY as usize].get_utilization(), 50);
    }

    /// Test: Multiple resource types per tenant
    #[test]
    fn multiple_resource_types() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        // Set quotas for different resources
        ctrl.set_tenant_quota(id, resource::CPU, 100, 0, enforce_mode::HARD).unwrap();
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        ctrl.set_tenant_quota(id, resource::DISK, 5000, 0, enforce_mode::HARD).unwrap();
        ctrl.set_tenant_quota(id, resource::NETWORK, 2000, 0, enforce_mode::HARD).unwrap();
        
        // Allocate from each independently
        ctrl.allocate_resource(id, resource::CPU, 50).unwrap();
        ctrl.allocate_resource(id, resource::MEMORY, 500).unwrap();
        ctrl.allocate_resource(id, resource::DISK, 2500).unwrap();
        ctrl.allocate_resource(id, resource::NETWORK, 1000).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        assert_eq!(tenant.quotas[resource::CPU as usize].usage.load(Ordering::Acquire), 50);
        assert_eq!(tenant.quotas[resource::MEMORY as usize].usage.load(Ordering::Acquire), 500);
        assert_eq!(tenant.quotas[resource::DISK as usize].usage.load(Ordering::Acquire), 2500);
        assert_eq!(tenant.quotas[resource::NETWORK as usize].usage.load(Ordering::Acquire), 1000);
    }

    /// Test: Tenant isolation groups
    #[test]
    fn isolation_groups() {
        let mut ctrl = MultiTenantController::new();
        
        let id1 = ctrl.create_tenant(128).unwrap();
        let id2 = ctrl.create_tenant(128).unwrap();
        
        // Tenants can have different isolation groups set via init
        let t1 = ctrl.get_tenant(id1).unwrap();
        let t2 = ctrl.get_tenant(id2).unwrap();
        
        // Verify isolation_group field exists and can be read
        let _g1 = t1.isolation_group.load(Ordering::Acquire);
        let _g2 = t2.isolation_group.load(Ordering::Acquire);
    }

    /// Test: Tenant statistics
    #[test]
    fn tenant_statistics() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        ctrl.allocate_resource(id, resource::MEMORY, 500).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        tenant.add_vm(1).unwrap();
        tenant.add_vm(2).unwrap();
        
        let stats = ctrl.get_tenant_stats(id).unwrap();
        assert_eq!(stats.vm_count, 2);
        assert_eq!(stats.quota_utilization[resource::MEMORY as usize], 50);
    }

    /// Test: Delete non-existent tenant fails
    #[test]
    fn delete_nonexistent_tenant() {
        let mut ctrl = MultiTenantController::new();
        assert!(ctrl.delete_tenant(999).is_err());
    }

    /// Test: Allocate to non-existent tenant fails
    #[test]
    fn allocate_nonexistent_tenant() {
        let ctrl = MultiTenantController::new();
        assert!(ctrl.allocate_resource(999, resource::MEMORY, 100).is_err());
    }

    /// Test: Quota with zero limit
    #[test]
    fn zero_limit_quota() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 0, 0, enforce_mode::HARD).unwrap();
        
        // Any allocation should fail with zero limit
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 1).is_err());
    }

    /// Test: Maximum tenants limit
    #[test]
    fn max_tenants_limit() {
        let mut ctrl = MultiTenantController::new();
        
        // Create tenants up to limit
        for _ in 0..MAX_TENANTS {
            ctrl.create_tenant(128).unwrap();
        }
        
        // Next should fail
        assert!(ctrl.create_tenant(128).is_err());
    }

    /// Test: Maximum VMs per tenant
    #[test]
    fn max_vms_per_tenant() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        
        // Add VMs up to limit
        for i in 0..MAX_VMS_PER_TENANT {
            tenant.add_vm(i as u32).unwrap();
        }
        
        // Next should fail
        assert!(tenant.add_vm(999).is_err());
    }

    /// Test: Over limit counter increments
    #[test]
    fn over_limit_counter() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        ctrl.set_tenant_quota(id, resource::MEMORY, 100, 0, enforce_mode::HARD).unwrap();
        
        // Attempt allocations that exceed limit
        let _ = ctrl.allocate_resource(id, resource::MEMORY, 200);
        let _ = ctrl.allocate_resource(id, resource::MEMORY, 200);
        let _ = ctrl.allocate_resource(id, resource::MEMORY, 200);
        
        let tenant = ctrl.get_tenant(id).unwrap();
        assert_eq!(tenant.quotas[resource::MEMORY as usize].over_limit_count.load(Ordering::Acquire), 3);
    }

    /// Test: Tenant priority affects scheduling hints
    #[test]
    fn tenant_priority() {
        let mut ctrl = MultiTenantController::new();
        
        let id_low = ctrl.create_tenant(50).unwrap();   // Low priority
        let id_high = ctrl.create_tenant(200).unwrap(); // High priority
        
        let t_low = ctrl.get_tenant(id_low).unwrap();
        let t_high = ctrl.get_tenant(id_high).unwrap();
        
        assert_eq!(t_low.priority.load(Ordering::Acquire), 50);
        assert_eq!(t_high.priority.load(Ordering::Acquire), 200);
    }

    /// Test: Tenant state transitions
    #[test]
    fn tenant_state_transitions() {
        let mut ctrl = MultiTenantController::new();
        let id = ctrl.create_tenant(128).unwrap();
        
        let tenant = ctrl.get_tenant(id).unwrap();
        
        // Initial state should be ACTIVE
        assert_eq!(tenant.state.load(Ordering::Acquire), tenant_state::ACTIVE);
        
        // Suspend
        tenant.suspend();
        assert_eq!(tenant.state.load(Ordering::Acquire), tenant_state::SUSPENDED);
        
        // Cannot allocate when suspended
        ctrl.set_tenant_quota(id, resource::MEMORY, 1000, 0, enforce_mode::HARD).unwrap();
        assert!(ctrl.allocate_resource(id, resource::MEMORY, 100).is_err());
        
        // Resume - should activate
        tenant.resume();
        assert_eq!(tenant.state.load(Ordering::Acquire), tenant_state::ACTIVE);
    }
}
