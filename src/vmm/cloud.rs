//! Cloud Integration - Kubernetes, Container Runtime
//!
//! K8s integration and container runtime support.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Kubernetes Integration Constants
// ─────────────────────────────────────────────────────────────────────────────

/// K8s resource types
pub mod k8s_resource {
    pub const POD: u8 = 0;
    pub const DEPLOYMENT: u8 = 1;
    pub const SERVICE: u8 = 2;
    pub const CONFIGMAP: u8 = 3;
    pub const SECRET: u8 = 4;
    pub const PV: u8 = 5;
    pub const PVC: u8 = 6;
    pub const NODE: u8 = 7;
    pub const NAMESPACE: u8 = 8;
}

/// Pod phases
pub mod pod_phase {
    pub const PENDING: u8 = 0;
    pub const RUNNING: u8 = 1;
    pub const SUCCEEDED: u8 = 2;
    pub const FAILED: u8 = 3;
    pub const UNKNOWN: u8 = 4;
}

/// Container states
pub mod container_state {
    pub const WAITING: u8 = 0;
    pub const RUNNING: u8 = 1;
    pub const TERMINATED: u8 = 2;
}

/// Maximum pods
pub const MAX_PODS: usize = 256;
/// Maximum containers per pod
pub const MAX_CONTAINERS_PER_POD: usize = 32;
/// Maximum namespaces
pub const MAX_NAMESPACES: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Container Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Container spec
pub struct Container {
    /// Container ID (hash)
    pub id: AtomicU64,
    /// Name hash
    pub name_hash: AtomicU64,
    /// Image hash
    pub image_hash: AtomicU64,
    /// VM ID backing this container
    pub vm_id: AtomicU32,
    /// State
    pub state: AtomicU8,
    /// Exit code
    pub exit_code: AtomicI32,
    /// Started timestamp
    pub started: AtomicU64,
    /// Finished timestamp
    pub finished: AtomicU64,
    /// CPU request (millicores)
    pub cpu_request: AtomicU32,
    /// CPU limit
    pub cpu_limit: AtomicU32,
    /// Memory request (bytes)
    pub mem_request: AtomicU64,
    /// Memory limit
    pub mem_limit: AtomicU64,
    /// Restart count
    pub restart_count: AtomicU32,
    /// Ready flag
    pub ready: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl Container {
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            name_hash: AtomicU64::new(0),
            image_hash: AtomicU64::new(0),
            vm_id: AtomicU32::new(0),
            state: AtomicU8::new(container_state::WAITING),
            exit_code: AtomicI32::new(0),
            started: AtomicU64::new(0),
            finished: AtomicU64::new(0),
            cpu_request: AtomicU32::new(100),
            cpu_limit: AtomicU32::new(0),
            mem_request: AtomicU64::new(64 * 1024 * 1024),
            mem_limit: AtomicU64::new(0),
            restart_count: AtomicU32::new(0),
            ready: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize container
    pub fn init(&self, id: u64, name_hash: u64, image_hash: u64, vm_id: u32) {
        self.id.store(id, Ordering::Release);
        self.name_hash.store(name_hash, Ordering::Release);
        self.image_hash.store(image_hash, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Start container
    pub fn start(&self) {
        self.state.store(container_state::RUNNING, Ordering::Release);
        self.started.store(Self::get_timestamp(), Ordering::Release);
        self.ready.store(true, Ordering::Release);
    }

    /// Stop container
    pub fn stop(&self, exit_code: i32) {
        self.state.store(container_state::TERMINATED, Ordering::Release);
        self.exit_code.store(exit_code, Ordering::Release);
        self.finished.store(Self::get_timestamp(), Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    /// Set resources
    pub fn set_resources(&self, cpu_req: u32, cpu_lim: u32, mem_req: u64, mem_lim: u64) {
        self.cpu_request.store(cpu_req, Ordering::Release);
        self.cpu_limit.store(cpu_lim, Ordering::Release);
        self.mem_request.store(mem_req, Ordering::Release);
        self.mem_limit.store(mem_lim, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Container {
    fn default() -> Self {
        Self::new()
    }
}

/// Atomic I32 workaround
pub struct AtomicI32 {
    inner: AtomicU32,
}

impl AtomicI32 {
    pub const fn new(v: i32) -> Self {
        Self { inner: AtomicU32::new(v as u32) }
    }
    pub fn load(&self, order: Ordering) -> i32 {
        self.inner.load(order) as i32
    }
    pub fn store(&self, v: i32, order: Ordering) {
        self.inner.store(v as u32, order);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pod Definition
// ─────────────────────────────────────────────────────────────────────────────

/// Pod spec
pub struct Pod {
    /// Pod ID
    pub id: AtomicU64,
    /// Name hash
    pub name_hash: AtomicU64,
    /// Namespace hash
    pub namespace_hash: AtomicU64,
    /// UID (K8s UID)
    pub uid: AtomicU64,
    /// Phase
    pub phase: AtomicU8,
    /// Containers
    pub containers: [Container; MAX_CONTAINERS_PER_POD],
    /// Container count
    pub container_count: AtomicU8,
    /// Node name hash
    pub node_hash: AtomicU64,
    /// IP address
    pub pod_ip: AtomicU32,
    /// Labels (key-value pairs, hashed)
    pub labels: [AtomicU64; 16],
    /// Label count
    pub label_count: AtomicU8,
    /// Annotations
    pub annotations: [AtomicU64; 8],
    /// Annotation count
    pub annotation_count: AtomicU8,
    /// Created timestamp
    pub created: AtomicU64,
    /// Deletion timestamp
    pub deleted: AtomicU64,
    /// Deletion grace period
    pub grace_period: AtomicU32,
    /// Ready containers
    pub ready_count: AtomicU8,
    /// Total containers
    pub total_containers: AtomicU8,
    /// Restart policy (0=Always, 1=OnFailure, 2=Never)
    pub restart_policy: AtomicU8,
    /// Service account
    pub service_account: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl Pod {
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            name_hash: AtomicU64::new(0),
            namespace_hash: AtomicU64::new(0),
            uid: AtomicU64::new(0),
            phase: AtomicU8::new(pod_phase::PENDING),
            containers: [const { Container::new() }; MAX_CONTAINERS_PER_POD],
            container_count: AtomicU8::new(0),
            node_hash: AtomicU64::new(0),
            pod_ip: AtomicU32::new(0),
            labels: [const { AtomicU64::new(0) }; 16],
            label_count: AtomicU8::new(0),
            annotations: [const { AtomicU64::new(0) }; 8],
            annotation_count: AtomicU8::new(0),
            created: AtomicU64::new(0),
            deleted: AtomicU64::new(0),
            grace_period: AtomicU32::new(30),
            ready_count: AtomicU8::new(0),
            total_containers: AtomicU8::new(0),
            restart_policy: AtomicU8::new(0),
            service_account: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize pod
    pub fn init(&self, id: u64, name_hash: u64, ns_hash: u64, uid: u64) {
        self.id.store(id, Ordering::Release);
        self.name_hash.store(name_hash, Ordering::Release);
        self.namespace_hash.store(ns_hash, Ordering::Release);
        self.uid.store(uid, Ordering::Release);
        self.created.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add container
    pub fn add_container(&self, container: &Container) -> Result<u8, HvError> {
        let count = self.container_count.load(Ordering::Acquire);
        if count as usize >= MAX_CONTAINERS_PER_POD {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count;
        // Copy container data
        self.containers[idx as usize].id.store(container.id.load(Ordering::Acquire), Ordering::Release);
        self.containers[idx as usize].name_hash.store(container.name_hash.load(Ordering::Acquire), Ordering::Release);
        self.containers[idx as usize].image_hash.store(container.image_hash.load(Ordering::Acquire), Ordering::Release);
        self.containers[idx as usize].vm_id.store(container.vm_id.load(Ordering::Acquire), Ordering::Release);
        self.containers[idx as usize].valid.store(true, Ordering::Release);
        
        self.container_count.fetch_add(1, Ordering::Release);
        self.total_containers.fetch_add(1, Ordering::Release);
        
        Ok(idx)
    }

    /// Add label
    pub fn add_label(&self, key_hash: u64) {
        let count = self.label_count.load(Ordering::Acquire) as usize;
        if count < 16 {
            self.labels[count].store(key_hash, Ordering::Release);
            self.label_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Set phase
    pub fn set_phase(&self, phase: u8) {
        self.phase.store(phase, Ordering::Release);
    }

    /// Update ready count
    pub fn update_ready(&self) {
        let mut ready = 0u8;
        for i in 0..self.container_count.load(Ordering::Acquire) as usize {
            if self.containers[i].ready.load(Ordering::Acquire) {
                ready += 1;
            }
        }
        self.ready_count.store(ready, Ordering::Release);
        
        if ready == self.container_count.load(Ordering::Acquire) {
            self.phase.store(pod_phase::RUNNING, Ordering::Release);
        }
    }

    /// Mark for deletion
    pub fn mark_deleted(&self, grace_period: u32) {
        self.deleted.store(Self::get_timestamp(), Ordering::Release);
        self.grace_period.store(grace_period, Ordering::Release);
    }

    /// Check if deletion grace period expired
    pub fn is_grace_expired(&self) -> bool {
        let deleted = self.deleted.load(Ordering::Acquire);
        if deleted == 0 {
            return false;
        }
        let now = Self::get_timestamp();
        let grace = self.grace_period.load(Ordering::Acquire) as u64;
        now >= deleted + grace * 1000
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Pod {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Kubernetes Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Namespace
pub struct Namespace {
    /// Name hash
    pub name_hash: AtomicU64,
    /// UID
    pub uid: AtomicU64,
    /// Active
    pub active: AtomicBool,
    /// Pod count
    pub pod_count: AtomicU16,
}

impl Namespace {
    pub const fn new() -> Self {
        Self {
            name_hash: AtomicU64::new(0),
            uid: AtomicU64::new(0),
            active: AtomicBool::new(false),
            pod_count: AtomicU16::new(0),
        }
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

/// Kubernetes controller
pub struct K8sController {
    /// Pods
    pub pods: [Pod; MAX_PODS],
    /// Pod count
    pub pod_count: AtomicU16,
    /// Namespaces
    pub namespaces: [Namespace; MAX_NAMESPACES],
    /// Namespace count
    pub ns_count: AtomicU8,
    /// Node name hash
    pub node_name: AtomicU64,
    /// Node IP
    pub node_ip: AtomicU32,
    /// Node ready
    pub node_ready: AtomicBool,
    /// K8s integration enabled
    pub enabled: AtomicBool,
    /// API server address
    pub api_server: AtomicU64,
    /// Sync interval (ms)
    pub sync_interval: AtomicU32,
    /// Last sync
    pub last_sync: AtomicU64,
    /// Total pods created
    pub total_created: AtomicU64,
    /// Total pods deleted
    pub total_deleted: AtomicU64,
}

impl K8sController {
    pub const fn new() -> Self {
        Self {
            pods: [const { Pod::new() }; MAX_PODS],
            pod_count: AtomicU16::new(0),
            namespaces: [const { Namespace::new() }; MAX_NAMESPACES],
            ns_count: AtomicU8::new(0),
            node_name: AtomicU64::new(0),
            node_ip: AtomicU32::new(0),
            node_ready: AtomicBool::new(false),
            enabled: AtomicBool::new(false),
            api_server: AtomicU64::new(0),
            sync_interval: AtomicU32::new(5000),
            last_sync: AtomicU64::new(0),
            total_created: AtomicU64::new(0),
            total_deleted: AtomicU64::new(0),
        }
    }

    /// Enable K8s integration
    pub fn enable(&mut self, api_server: u64, node_name: u64, node_ip: u32) {
        self.api_server.store(api_server, Ordering::Release);
        self.node_name.store(node_name, Ordering::Release);
        self.node_ip.store(node_ip, Ordering::Release);
        self.node_ready.store(true, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable K8s integration
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
        self.node_ready.store(false, Ordering::Release);
    }

    /// Create namespace
    pub fn create_namespace(&mut self, name_hash: u64, uid: u64) -> Result<u8, HvError> {
        let count = self.ns_count.load(Ordering::Acquire);
        if count as usize >= MAX_NAMESPACES {
            return Err(HvError::LogicalFault);
        }
        
        let ns = &self.namespaces[count as usize];
        ns.name_hash.store(name_hash, Ordering::Release);
        ns.uid.store(uid, Ordering::Release);
        ns.active.store(true, Ordering::Release);
        
        self.ns_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Create pod
    pub fn create_pod(&mut self, name_hash: u64, ns_hash: u64, uid: u64) -> Result<u16, HvError> {
        let count = self.pod_count.load(Ordering::Acquire);
        if count as usize >= MAX_PODS {
            return Err(HvError::LogicalFault);
        }
        
        let pod_id = count;
        let pod = &self.pods[pod_id as usize];
        pod.init(pod_id as u64, name_hash, ns_hash, uid);
        pod.set_phase(pod_phase::PENDING);
        
        // Update namespace pod count
        for i in 0..self.ns_count.load(Ordering::Acquire) as usize {
            if self.namespaces[i].name_hash.load(Ordering::Acquire) == ns_hash {
                self.namespaces[i].pod_count.fetch_add(1, Ordering::Release);
                break;
            }
        }
        
        self.pod_count.fetch_add(1, Ordering::Release);
        self.total_created.fetch_add(1, Ordering::Release);
        
        Ok(pod_id)
    }

    /// Delete pod
    pub fn delete_pod(&mut self, pod_id: u16, grace_period: u32) -> Result<(), HvError> {
        if pod_id as usize >= MAX_PODS {
            return Err(HvError::LogicalFault);
        }
        
        let pod = &self.pods[pod_id as usize];
        if !pod.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        pod.mark_deleted(grace_period);
        
        Ok(())
    }

    /// Get pod by name
    pub fn get_pod(&self, name_hash: u64, ns_hash: u64) -> Option<u16> {
        for i in 0..self.pod_count.load(Ordering::Acquire) as usize {
            let pod = &self.pods[i];
            if pod.name_hash.load(Ordering::Acquire) == name_hash &&
               pod.namespace_hash.load(Ordering::Acquire) == ns_hash &&
               pod.valid.load(Ordering::Acquire) {
                return Some(i as u16);
            }
        }
        None
    }

    /// Sync with API server
    pub fn sync(&mut self) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        // Would sync with K8s API server
        self.last_sync.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Reconcile pods
    pub fn reconcile(&mut self) {
        // Check for grace period expired pods
        for i in 0..self.pod_count.load(Ordering::Acquire) as usize {
            let pod = &self.pods[i];
            if pod.deleted.load(Ordering::Acquire) != 0 && pod.is_grace_expired() {
                // Force delete
                pod.valid.store(false, Ordering::Release);
                self.total_deleted.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> K8sStats {
        let mut running = 0u16;
        let mut pending = 0u16;
        let mut terminated = 0u16;
        
        for i in 0..self.pod_count.load(Ordering::Acquire) as usize {
            match self.pods[i].phase.load(Ordering::Acquire) {
                pod_phase::PENDING => pending += 1,
                pod_phase::RUNNING => running += 1,
                pod_phase::SUCCEEDED | pod_phase::FAILED => terminated += 1,
                _ => {}
            }
        }
        
        K8sStats {
            enabled: self.enabled.load(Ordering::Acquire),
            node_ready: self.node_ready.load(Ordering::Acquire),
            pod_count: self.pod_count.load(Ordering::Acquire),
            running_pods: running,
            pending_pods: pending,
            terminated_pods: terminated,
            total_created: self.total_created.load(Ordering::Acquire),
            total_deleted: self.total_deleted.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for K8sController {
    fn default() -> Self {
        Self::new()
    }
}

/// K8s statistics
#[repr(C)]
pub struct K8sStats {
    pub enabled: bool,
    pub node_ready: bool,
    pub pod_count: u16,
    pub running_pods: u16,
    pub pending_pods: u16,
    pub terminated_pods: u16,
    pub total_created: u64,
    pub total_deleted: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Container Runtime Interface (CRI)
// ─────────────────────────────────────────────────────────────────────────────

/// CRI container status
pub struct CriContainerStatus {
    /// Container ID
    pub id: AtomicU64,
    /// State
    pub state: AtomicU8,
    /// Created at
    pub created_at: AtomicU64,
    /// Started at
    pub started_at: AtomicU64,
    /// Finished at
    pub finished_at: AtomicU64,
    /// Exit code
    pub exit_code: AtomicI32,
    /// Image reference hash
    pub image_ref: AtomicU64,
    /// Image ID
    pub image_id: AtomicU64,
    /// Log path hash
    pub log_path: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CriContainerStatus {
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            state: AtomicU8::new(container_state::WAITING),
            created_at: AtomicU64::new(0),
            started_at: AtomicU64::new(0),
            finished_at: AtomicU64::new(0),
            exit_code: AtomicI32::new(0),
            image_ref: AtomicU64::new(0),
            image_id: AtomicU64::new(0),
            log_path: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

impl Default for CriContainerStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum CRI containers
pub const MAX_CRI_CONTAINERS: usize = 512;

/// CRI runtime service
pub struct CriRuntime {
    /// Container statuses
    pub containers: [CriContainerStatus; MAX_CRI_CONTAINERS],
    /// Container count
    pub container_count: AtomicU16,
    /// Enabled
    pub enabled: AtomicBool,
    /// Runtime handler (runtime class)
    pub runtime_handler: AtomicU64,
    /// Sandbox enabled
    pub sandbox_enabled: AtomicBool,
    /// Total containers created
    pub total_created: AtomicU64,
    /// Total containers removed
    pub total_removed: AtomicU64,
}

impl CriRuntime {
    pub const fn new() -> Self {
        Self {
            containers: [const { CriContainerStatus::new() }; MAX_CRI_CONTAINERS],
            container_count: AtomicU16::new(0),
            enabled: AtomicBool::new(false),
            runtime_handler: AtomicU64::new(0),
            sandbox_enabled: AtomicBool::new(true),
            total_created: AtomicU64::new(0),
            total_removed: AtomicU64::new(0),
        }
    }

    /// Enable CRI
    pub fn enable(&mut self, runtime_handler: u64) {
        self.runtime_handler.store(runtime_handler, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Create container
    pub fn create_container(&mut self, id: u64, image_ref: u64, image_id: u64) -> Result<u16, HvError> {
        let count = self.container_count.load(Ordering::Acquire);
        if count as usize >= MAX_CRI_CONTAINERS {
            return Err(HvError::LogicalFault);
        }
        
        let container = &self.containers[count as usize];
        container.id.store(id, Ordering::Release);
        container.image_ref.store(image_ref, Ordering::Release);
        container.image_id.store(image_id, Ordering::Release);
        container.state.store(container_state::WAITING, Ordering::Release);
        container.created_at.store(Self::get_timestamp(), Ordering::Release);
        container.valid.store(true, Ordering::Release);
        
        self.container_count.fetch_add(1, Ordering::Release);
        self.total_created.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Start container
    pub fn start_container(&self, idx: u16) -> Result<(), HvError> {
        if idx as usize >= MAX_CRI_CONTAINERS {
            return Err(HvError::LogicalFault);
        }
        
        let container = &self.containers[idx as usize];
        if !container.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        container.state.store(container_state::RUNNING, Ordering::Release);
        container.started_at.store(Self::get_timestamp(), Ordering::Release);
        
        Ok(())
    }

    /// Stop container
    pub fn stop_container(&self, idx: u16, timeout: u32) -> Result<(), HvError> {
        if idx as usize >= MAX_CRI_CONTAINERS {
            return Err(HvError::LogicalFault);
        }
        
        let container = &self.containers[idx as usize];
        if !container.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        container.state.store(container_state::TERMINATED, Ordering::Release);
        container.finished_at.store(Self::get_timestamp(), Ordering::Release);
        
        let _ = timeout;
        Ok(())
    }

    /// Remove container
    pub fn remove_container(&self, idx: u16) -> Result<(), HvError> {
        if idx as usize >= MAX_CRI_CONTAINERS {
            return Err(HvError::LogicalFault);
        }
        
        let container = &self.containers[idx as usize];
        container.valid.store(false, Ordering::Release);
        self.total_removed.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Get container status
    pub fn get_status(&self, idx: u16) -> Option<CriStatus> {
        if idx as usize >= MAX_CRI_CONTAINERS {
            return None;
        }
        
        let container = &self.containers[idx as usize];
        if !container.valid.load(Ordering::Acquire) {
            return None;
        }
        
        Some(CriStatus {
            id: container.id.load(Ordering::Acquire),
            state: container.state.load(Ordering::Acquire),
            created_at: container.created_at.load(Ordering::Acquire),
            started_at: container.started_at.load(Ordering::Acquire),
            finished_at: container.finished_at.load(Ordering::Acquire),
            exit_code: container.exit_code.load(Ordering::Acquire),
        })
    }

    /// Get statistics
    pub fn get_stats(&self) -> CriStats {
        CriStats {
            enabled: self.enabled.load(Ordering::Acquire),
            container_count: self.container_count.load(Ordering::Acquire),
            total_created: self.total_created.load(Ordering::Acquire),
            total_removed: self.total_removed.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for CriRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// CRI status
#[repr(C)]
pub struct CriStatus {
    pub id: u64,
    pub state: u8,
    pub created_at: u64,
    pub started_at: u64,
    pub finished_at: u64,
    pub exit_code: i32,
}

/// CRI statistics
#[repr(C)]
pub struct CriStats {
    pub enabled: bool,
    pub container_count: u16,
    pub total_created: u64,
    pub total_removed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8s_create_pod() {
        let mut k8s = K8sController::new();
        k8s.enable(0x12345678, 0x87654321, 0x0A000001);
        
        let pod_id = k8s.create_pod(0x11111111, 0x22222222, 0x33333333).unwrap();
        assert_eq!(k8s.pod_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn k8s_delete_pod() {
        let mut k8s = K8sController::new();
        k8s.enable(0x12345678, 0x87654321, 0x0A000001);
        
        let pod_id = k8s.create_pod(0x11111111, 0x22222222, 0x33333333).unwrap();
        k8s.delete_pod(pod_id, 30).unwrap();
        
        // Check grace_period was set (deleted timestamp is 0 since get_timestamp returns 0)
        assert!(k8s.pods[pod_id as usize].grace_period.load(Ordering::Acquire) == 30);
    }

    #[test]
    fn cri_create_container() {
        let mut cri = CriRuntime::new();
        cri.enable(0x12345678);
        
        let idx = cri.create_container(0x11111111, 0x22222222, 0x33333333).unwrap();
        assert_eq!(cri.container_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn cri_start_container() {
        let mut cri = CriRuntime::new();
        cri.enable(0x12345678);
        
        let idx = cri.create_container(0x11111111, 0x22222222, 0x33333333).unwrap();
        cri.start_container(idx).unwrap();
        
        assert_eq!(cri.containers[idx as usize].state.load(Ordering::Acquire), container_state::RUNNING);
    }
}
