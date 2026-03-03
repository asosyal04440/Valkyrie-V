//! Advanced Security - SELinux, Seccomp, Sandboxing
//!
//! Mandatory access control and process isolation.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// SELinux Constants
// ─────────────────────────────────────────────────────────────────────────────

/// SELinux enforcement modes
pub mod selinux_mode {
    pub const DISABLED: u8 = 0;
    pub const PERMISSIVE: u8 = 1;
    pub const ENFORCING: u8 = 2;
}

/// SELinux object classes
pub mod obj_class {
    pub const PROCESS: u16 = 1;
    pub const FILE: u16 = 2;
    pub const DIR: u16 = 3;
    pub const SOCKET: u16 = 4;
    pub const CHAR_DEV: u16 = 5;
    pub const BLOCK_DEV: u16 = 6;
    pub const NETIF: u16 = 7;
    pub const NODE: u16 = 8;
    pub const PORT: u16 = 9;
    pub const VM: u16 = 10;
    pub const VCPU: u16 = 11;
    pub const MEMORY: u16 = 12;
    pub const DEVICE: u16 = 13;
}

/// SELinux permissions
pub mod perm {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const CREATE: u32 = 1 << 3;
    pub const DESTROY: u32 = 1 << 4;
    pub const TRANSITION: u32 = 1 << 5;
    pub const ENTRYPOINT: u32 = 1 << 6;
    pub const RELABEL: u32 = 1 << 7;
    pub const ASSOCIATE: u32 = 1 << 8;
    pub const SETATTR: u32 = 1 << 9;
    pub const GETATTR: u32 = 1 << 10;
    pub const IOCTL: u32 = 1 << 11;
    pub const MAP: u32 = 1 << 12;
    pub const MMAP: u32 = 1 << 13;
    pub const MPROTECT: u32 = 1 << 14;
}

/// Maximum security contexts
pub const MAX_SELINUX_CONTEXTS: usize = 256;
/// Maximum AVC entries
pub const MAX_AVC_ENTRIES: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// SELinux Security Context
// ─────────────────────────────────────────────────────────────────────────────

/// Security context (SID - Security ID)
pub struct SecurityContext {
    /// Security ID
    pub sid: AtomicU32,
    /// User component
    pub user: AtomicU16,
    /// Role component
    pub role: AtomicU16,
    /// Type component
    pub type_: AtomicU32,
    /// MLS range (low)
    pub mls_low: AtomicU8,
    /// MLS range (high)
    pub mls_high: AtomicU8,
    /// Valid
    pub valid: AtomicBool,
}

impl SecurityContext {
    pub const fn new() -> Self {
        Self {
            sid: AtomicU32::new(0),
            user: AtomicU16::new(0),
            role: AtomicU16::new(0),
            type_: AtomicU32::new(0),
            mls_low: AtomicU8::new(0),
            mls_high: AtomicU8::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize context
    pub fn init(&self, sid: u32, user: u16, role: u16, type_: u32, mls_low: u8, mls_high: u8) {
        self.sid.store(sid, Ordering::Release);
        self.user.store(user, Ordering::Release);
        self.role.store(role, Ordering::Release);
        self.type_.store(type_, Ordering::Release);
        self.mls_low.store(mls_low, Ordering::Release);
        self.mls_high.store(mls_high, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check if context dominates another (MLS)
    pub fn dominates(&self, other: &SecurityContext) -> bool {
        let low = self.mls_low.load(Ordering::Acquire);
        let high = self.mls_high.load(Ordering::Acquire);
        let other_low = other.mls_low.load(Ordering::Acquire);
        let other_high = other.mls_high.load(Ordering::Acquire);
        
        low <= other_low && high >= other_high
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SELinux Access Vector Cache (AVC)
// ─────────────────────────────────────────────────────────────────────────────

/// AVC entry
pub struct AvcEntry {
    /// Source SID
    pub source_sid: AtomicU32,
    /// Target SID
    pub target_sid: AtomicU32,
    /// Target class
    pub target_class: AtomicU16,
    /// Allowed permissions
    pub allowed: AtomicU32,
    /// Audited permissions (allow)
    pub audit_allow: AtomicU32,
    /// Audited permissions (deny)
    pub audit_deny: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
    /// Last used timestamp
    pub last_used: AtomicU64,
}

impl AvcEntry {
    pub const fn new() -> Self {
        Self {
            source_sid: AtomicU32::new(0),
            target_sid: AtomicU32::new(0),
            target_class: AtomicU16::new(0),
            allowed: AtomicU32::new(0),
            audit_allow: AtomicU32::new(0),
            audit_deny: AtomicU32::new(0),
            valid: AtomicBool::new(false),
            last_used: AtomicU64::new(0),
        }
    }

    /// Check permission
    pub fn check_permission(&self, perm: u32) -> bool {
        (self.allowed.load(Ordering::Acquire) & perm) != 0
    }

    /// Update last used
    pub fn touch(&self) {
        self.last_used.store(Self::get_timestamp(), Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for AvcEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SELinux Policy Database
// ─────────────────────────────────────────────────────────────────────────────

/// Type enforcement rule
pub struct TeRule {
    /// Source type
    pub source_type: AtomicU32,
    /// Target type
    pub target_type: AtomicU32,
    /// Target class
    pub target_class: AtomicU16,
    /// Permissions
    pub perms: AtomicU32,
    /// Rule type (allow/deny/audit)
    pub rule_type: AtomicU8,
    /// Valid
    pub valid: AtomicBool,
}

impl TeRule {
    pub const fn new() -> Self {
        Self {
            source_type: AtomicU32::new(0),
            target_type: AtomicU32::new(0),
            target_class: AtomicU16::new(0),
            perms: AtomicU32::new(0),
            rule_type: AtomicU8::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

impl Default for TeRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum TE rules
pub const MAX_TE_RULES: usize = 8192;

/// SELinux policy database
pub struct SelinuxPolicy {
    /// Security contexts
    pub contexts: [SecurityContext; MAX_SELINUX_CONTEXTS],
    /// Context count
    pub context_count: AtomicU32,
    /// Type enforcement rules
    pub te_rules: [TeRule; MAX_TE_RULES],
    /// TE rule count
    pub te_rule_count: AtomicU32,
    /// AVC entries
    pub avc: [AvcEntry; MAX_AVC_ENTRIES],
    /// AVC entry count
    pub avc_count: AtomicU32,
    /// Enforcement mode
    pub enforce_mode: AtomicU8,
    /// Policy version
    pub policy_version: AtomicU32,
    /// Policy capabilities
    pub capabilities: AtomicU32,
    /// Deny unknown
    pub deny_unknown: AtomicBool,
}

impl SelinuxPolicy {
    pub const fn new() -> Self {
        Self {
            contexts: [const { SecurityContext::new() }; MAX_SELINUX_CONTEXTS],
            context_count: AtomicU32::new(0),
            te_rules: [const { TeRule::new() }; MAX_TE_RULES],
            te_rule_count: AtomicU32::new(0),
            avc: [const { AvcEntry::new() }; MAX_AVC_ENTRIES],
            avc_count: AtomicU32::new(0),
            enforce_mode: AtomicU8::new(selinux_mode::DISABLED),
            policy_version: AtomicU32::new(32),
            capabilities: AtomicU32::new(0),
            deny_unknown: AtomicBool::new(true),
        }
    }

    /// Enable SELinux
    pub fn enable(&mut self, mode: u8) {
        self.enforce_mode.store(mode, Ordering::Release);
    }

    /// Disable SELinux
    pub fn disable(&mut self) {
        self.enforce_mode.store(selinux_mode::DISABLED, Ordering::Release);
    }

    /// Add security context
    pub fn add_context(&mut self, user: u16, role: u16, type_: u32, mls_low: u8, mls_high: u8) -> Result<u32, HvError> {
        let count = self.context_count.load(Ordering::Acquire);
        if count as usize >= MAX_SELINUX_CONTEXTS {
            return Err(HvError::LogicalFault);
        }
        
        let sid = count + 1; // SID 0 is invalid
        let ctx = &self.contexts[count as usize];
        ctx.init(sid, user, role, type_, mls_low, mls_high);
        
        self.context_count.fetch_add(1, Ordering::Release);
        Ok(sid)
    }

    /// Add TE rule
    pub fn add_te_rule(&mut self, source_type: u32, target_type: u32, 
                       target_class: u16, perms: u32, rule_type: u8) -> Result<(), HvError> {
        let count = self.te_rule_count.load(Ordering::Acquire);
        if count as usize >= MAX_TE_RULES {
            return Err(HvError::LogicalFault);
        }
        
        let rule = &self.te_rules[count as usize];
        rule.source_type.store(source_type, Ordering::Release);
        rule.target_type.store(target_type, Ordering::Release);
        rule.target_class.store(target_class, Ordering::Release);
        rule.perms.store(perms, Ordering::Release);
        rule.rule_type.store(rule_type, Ordering::Release);
        rule.valid.store(true, Ordering::Release);
        
        self.te_rule_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Check permission
    pub fn check_permission(&self, source_sid: u32, target_sid: u32, 
                           target_class: u16, perm: u32) -> Result<bool, HvError> {
        let mode = self.enforce_mode.load(Ordering::Acquire);
        if mode == selinux_mode::DISABLED {
            return Ok(true);
        }
        
        // Check AVC cache first
        if let Some(entry) = self.avc_lookup(source_sid, target_sid, target_class) {
            entry.touch();
            let allowed = entry.check_permission(perm);
            return Ok(allowed);
        }
        
        // Look up in policy
        let source_ctx = self.get_context(source_sid)?;
        let target_ctx = self.get_context(target_sid)?;
        
        let allowed = self.policy_check(
            source_ctx.type_.load(Ordering::Acquire),
            target_ctx.type_.load(Ordering::Acquire),
            target_class,
            perm,
        );
        
        // Add to AVC cache
        self.avc_add(source_sid, target_sid, target_class, if allowed { perm } else { 0 });
        
        Ok(allowed)
    }

    /// Look up AVC entry
    fn avc_lookup(&self, source_sid: u32, target_sid: u32, target_class: u16) -> Option<&AvcEntry> {
        for i in 0..self.avc_count.load(Ordering::Acquire) as usize {
            let entry = &self.avc[i];
            if entry.source_sid.load(Ordering::Acquire) == source_sid &&
               entry.target_sid.load(Ordering::Acquire) == target_sid &&
               entry.target_class.load(Ordering::Acquire) == target_class {
                return Some(entry);
            }
        }
        None
    }

    /// Add AVC entry
    fn avc_add(&self, source_sid: u32, target_sid: u32, target_class: u16, allowed: u32) {
        let count = self.avc_count.load(Ordering::Acquire);
        if count as usize >= MAX_AVC_ENTRIES {
            // Would evict oldest entry
            return;
        }
        
        let entry = &self.avc[count as usize];
        entry.source_sid.store(source_sid, Ordering::Release);
        entry.target_sid.store(target_sid, Ordering::Release);
        entry.target_class.store(target_class, Ordering::Release);
        entry.allowed.store(allowed, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.avc_count.fetch_add(1, Ordering::Release);
    }

    /// Get context by SID
    fn get_context(&self, sid: u32) -> Result<&SecurityContext, HvError> {
        if sid == 0 || sid as usize > self.context_count.load(Ordering::Acquire) as usize {
            return Err(HvError::LogicalFault);
        }
        Ok(&self.contexts[(sid - 1) as usize])
    }

    /// Check policy rules
    fn policy_check(&self, source_type: u32, target_type: u32, target_class: u16, perm: u32) -> bool {
        let mut allowed = false;
        
        for i in 0..self.te_rule_count.load(Ordering::Acquire) as usize {
            let rule = &self.te_rules[i];
            if !rule.valid.load(Ordering::Acquire) {
                continue;
            }
            
            if rule.source_type.load(Ordering::Acquire) == source_type &&
               rule.target_type.load(Ordering::Acquire) == target_type &&
               rule.target_class.load(Ordering::Acquire) == target_class {
                if (rule.perms.load(Ordering::Acquire) & perm) != 0 {
                    match rule.rule_type.load(Ordering::Acquire) {
                        0 => allowed = true,  // allow
                        1 => return false,     // deny
                        _ => {}
                    }
                }
            }
        }
        
        allowed || !self.deny_unknown.load(Ordering::Acquire)
    }

    /// Get statistics
    pub fn get_stats(&self) -> SelinuxStats {
        SelinuxStats {
            enforce_mode: self.enforce_mode.load(Ordering::Acquire),
            context_count: self.context_count.load(Ordering::Acquire),
            te_rule_count: self.te_rule_count.load(Ordering::Acquire),
            avc_count: self.avc_count.load(Ordering::Acquire),
            policy_version: self.policy_version.load(Ordering::Acquire),
        }
    }
}

impl Default for SelinuxPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// SELinux statistics
#[repr(C)]
pub struct SelinuxStats {
    pub enforce_mode: u8,
    pub context_count: u32,
    pub te_rule_count: u32,
    pub avc_count: u32,
    pub policy_version: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Seccomp Filter
// ─────────────────────────────────────────────────────────────────────────────

/// Seccomp filter actions
pub mod seccomp_action {
    pub const KILL: u8 = 0;
    pub const TRAP: u8 = 1;
    pub const ERRNO: u8 = 2;
    pub const TRACE: u8 = 3;
    pub const LOG: u8 = 4;
    pub const ALLOW: u8 = 5;
}

/// Maximum seccomp rules
pub const MAX_SECCOMP_RULES: usize = 256;

/// Seccomp BPF instruction
#[repr(C)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// Seccomp filter rule
pub struct SeccompRule {
    /// Syscall number
    pub syscall_nr: AtomicI32,
    /// Action on match
    pub action: AtomicU8,
    /// Argument filters (up to 6 args)
    pub arg_filters: [AtomicU64; 6],
    /// Argument mask
    pub arg_mask: [AtomicU64; 6],
    /// Enabled
    pub enabled: AtomicBool,
}

impl SeccompRule {
    pub const fn new() -> Self {
        Self {
            syscall_nr: AtomicI32::new(0),
            action: AtomicU8::new(seccomp_action::ALLOW),
            arg_filters: [const { AtomicU64::new(0) }; 6],
            arg_mask: [const { AtomicU64::new(0) }; 6],
            enabled: AtomicBool::new(false),
        }
    }

    /// Check if syscall matches
    pub fn matches(&self, syscall_nr: i32, args: &[u64; 6]) -> bool {
        if !self.enabled.load(Ordering::Acquire) {
            return false;
        }
        
        if self.syscall_nr.load(Ordering::Acquire) != syscall_nr {
            return false;
        }
        
        // Check argument filters
        for i in 0..6 {
            let filter = self.arg_filters[i].load(Ordering::Acquire);
            let mask = self.arg_mask[i].load(Ordering::Acquire);
            if mask != 0 && (args[i] & mask) != filter {
                return false;
            }
        }
        
        true
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

/// Seccomp filter
pub struct SeccompFilter {
    /// Filter rules
    pub rules: [SeccompRule; MAX_SECCOMP_RULES],
    /// Rule count
    pub rule_count: AtomicU8,
    /// Default action
    pub default_action: AtomicU8,
    /// Filter enabled
    pub enabled: AtomicBool,
    /// Filter mode (0=disabled, 1=filter, 2=strict)
    pub mode: AtomicU8,
    /// Syscalls filtered
    pub syscalls_filtered: AtomicU64,
    /// Syscalls allowed
    pub syscalls_allowed: AtomicU64,
    /// Syscalls denied
    pub syscalls_denied: AtomicU64,
}

impl SeccompFilter {
    pub const fn new() -> Self {
        Self {
            rules: [const { SeccompRule::new() }; MAX_SECCOMP_RULES],
            rule_count: AtomicU8::new(0),
            default_action: AtomicU8::new(seccomp_action::KILL),
            enabled: AtomicBool::new(false),
            mode: AtomicU8::new(0),
            syscalls_filtered: AtomicU64::new(0),
            syscalls_allowed: AtomicU64::new(0),
            syscalls_denied: AtomicU64::new(0),
        }
    }

    /// Enable seccomp
    pub fn enable(&mut self, mode: u8) {
        self.enabled.store(true, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
    }

    /// Add rule
    pub fn add_rule(&mut self, syscall_nr: i32, action: u8, 
                    arg_filters: &[u64; 6], arg_mask: &[u64; 6]) -> Result<(), HvError> {
        let count = self.rule_count.load(Ordering::Acquire);
        if count as usize >= MAX_SECCOMP_RULES {
            return Err(HvError::LogicalFault);
        }
        
        let rule = &self.rules[count as usize];
        rule.syscall_nr.store(syscall_nr, Ordering::Release);
        rule.action.store(action, Ordering::Release);
        for i in 0..6 {
            rule.arg_filters[i].store(arg_filters[i], Ordering::Release);
            rule.arg_mask[i].store(arg_mask[i], Ordering::Release);
        }
        rule.enabled.store(true, Ordering::Release);
        
        self.rule_count.fetch_add(1, Ordering::Release);
        self.syscalls_filtered.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Check syscall
    pub fn check_syscall(&self, syscall_nr: i32, args: &[u64; 6]) -> u8 {
        if !self.enabled.load(Ordering::Acquire) {
            return seccomp_action::ALLOW;
        }
        
        // Strict mode - only allow read/write/exit/sigreturn
        if self.mode.load(Ordering::Acquire) == 2 {
            match syscall_nr {
                0 | 1 | 60 | 15 | 231 => return seccomp_action::ALLOW, // read/write/exit/rt_sigreturn/exit_group
                _ => return seccomp_action::KILL,
            }
        }
        
        // Filter mode - check rules
        for i in 0..self.rule_count.load(Ordering::Acquire) as usize {
            let rule = &self.rules[i];
            if rule.matches(syscall_nr, args) {
                let action = rule.action.load(Ordering::Acquire);
                match action {
                    seccomp_action::ALLOW => self.syscalls_allowed.fetch_add(1, Ordering::Release),
                    _ => self.syscalls_denied.fetch_add(1, Ordering::Release),
                };
                return action;
            }
        }
        
        // No match - use default
        self.syscalls_denied.fetch_add(1, Ordering::Release);
        self.default_action.load(Ordering::Acquire)
    }

    /// Get statistics
    pub fn get_stats(&self) -> SeccompStats {
        SeccompStats {
            enabled: self.enabled.load(Ordering::Acquire),
            mode: self.mode.load(Ordering::Acquire),
            rule_count: self.rule_count.load(Ordering::Acquire),
            syscalls_filtered: self.syscalls_filtered.load(Ordering::Acquire),
            syscalls_allowed: self.syscalls_allowed.load(Ordering::Acquire),
            syscalls_denied: self.syscalls_denied.load(Ordering::Acquire),
        }
    }
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self::new()
    }
}

/// Seccomp statistics
#[repr(C)]
pub struct SeccompStats {
    pub enabled: bool,
    pub mode: u8,
    pub rule_count: u8,
    pub syscalls_filtered: u64,
    pub syscalls_allowed: u64,
    pub syscalls_denied: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Sandboxing
// ─────────────────────────────────────────────────────────────────────────────

/// Sandbox profile
pub struct SandboxProfile {
    /// Profile ID
    pub profile_id: AtomicU32,
    /// Profile name hash
    pub name_hash: AtomicU64,
    /// File access mask
    pub file_access: AtomicU32,
    /// Network access mask
    pub network_access: AtomicU32,
    /// Device access mask
    pub device_access: AtomicU32,
    /// Allowed syscalls bitmap
    pub allowed_syscalls: [AtomicU64; 4], // 256 bits
    /// Memory limit
    pub memory_limit: AtomicU64,
    /// CPU limit (percentage)
    pub cpu_limit: AtomicU8,
    /// IO limit (bytes/sec)
    pub io_limit: AtomicU64,
    /// Network bandwidth limit
    pub net_limit: AtomicU64,
    /// Isolation level
    pub isolation_level: AtomicU8,
    /// Namespace flags
    pub namespace_flags: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
}

impl SandboxProfile {
    pub const fn new() -> Self {
        Self {
            profile_id: AtomicU32::new(0),
            name_hash: AtomicU64::new(0),
            file_access: AtomicU32::new(0),
            network_access: AtomicU32::new(0),
            device_access: AtomicU32::new(0),
            allowed_syscalls: [const { AtomicU64::new(0) }; 4],
            memory_limit: AtomicU64::new(0),
            cpu_limit: AtomicU8::new(100),
            io_limit: AtomicU64::new(0),
            net_limit: AtomicU64::new(0),
            isolation_level: AtomicU8::new(0),
            namespace_flags: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
        }
    }

    /// Set allowed syscall
    pub fn allow_syscall(&self, syscall_nr: u8) {
        let idx = (syscall_nr / 64) as usize;
        let bit = syscall_nr % 64;
        self.allowed_syscalls[idx].fetch_or(1 << bit, Ordering::Release);
    }

    /// Check if syscall allowed
    pub fn is_syscall_allowed(&self, syscall_nr: u8) -> bool {
        let idx = (syscall_nr / 64) as usize;
        let bit = syscall_nr % 64;
        (self.allowed_syscalls[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }
}

impl Default for SandboxProfile {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum sandbox profiles
pub const MAX_SANDBOX_PROFILES: usize = 64;

/// Sandbox controller
pub struct SandboxController {
    /// Profiles
    pub profiles: [SandboxProfile; MAX_SANDBOX_PROFILES],
    /// Profile count
    pub profile_count: AtomicU8,
    /// Default profile ID
    pub default_profile: AtomicU32,
    /// Sandbox enabled
    pub enabled: AtomicBool,
    /// Violations detected
    pub violations: AtomicU64,
    /// Processes sandboxed
    pub processes_sandboxed: AtomicU64,
}

impl SandboxController {
    pub const fn new() -> Self {
        Self {
            profiles: [const { SandboxProfile::new() }; MAX_SANDBOX_PROFILES],
            profile_count: AtomicU8::new(0),
            default_profile: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            violations: AtomicU64::new(0),
            processes_sandboxed: AtomicU64::new(0),
        }
    }

    /// Enable sandboxing
    pub fn enable(&mut self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Create profile
    pub fn create_profile(&mut self, name_hash: u64) -> Result<u32, HvError> {
        let count = self.profile_count.load(Ordering::Acquire);
        if count as usize >= MAX_SANDBOX_PROFILES {
            return Err(HvError::LogicalFault);
        }
        
        let profile = &self.profiles[count as usize];
        profile.profile_id.store(count as u32 + 1, Ordering::Release);
        profile.name_hash.store(name_hash, Ordering::Release);
        profile.enabled.store(true, Ordering::Release);
        
        self.profile_count.fetch_add(1, Ordering::Release);
        Ok(count as u32 + 1)
    }

    /// Apply profile to process
    pub fn apply_profile(&self, profile_id: u32) -> Result<(), HvError> {
        if profile_id == 0 || profile_id as usize > self.profile_count.load(Ordering::Acquire) as usize {
            return Err(HvError::LogicalFault);
        }
        
        self.processes_sandboxed.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Check file access
    pub fn check_file_access(&self, profile_id: u32, access_type: u32) -> bool {
        if !self.enabled.load(Ordering::Acquire) {
            return true;
        }
        
        if profile_id == 0 || profile_id as usize > MAX_SANDBOX_PROFILES {
            return false;
        }
        
        let profile = &self.profiles[(profile_id - 1) as usize];
        let allowed = (profile.file_access.load(Ordering::Acquire) & access_type) != 0;
        
        if !allowed {
            self.violations.fetch_add(1, Ordering::Release);
        }
        
        allowed
    }

    /// Check network access
    pub fn check_network_access(&self, profile_id: u32, access_type: u32) -> bool {
        if !self.enabled.load(Ordering::Acquire) {
            return true;
        }
        
        if profile_id == 0 || profile_id as usize > MAX_SANDBOX_PROFILES {
            return false;
        }
        
        let profile = &self.profiles[(profile_id - 1) as usize];
        let allowed = (profile.network_access.load(Ordering::Acquire) & access_type) != 0;
        
        if !allowed {
            self.violations.fetch_add(1, Ordering::Release);
        }
        
        allowed
    }

    /// Get statistics
    pub fn get_stats(&self) -> SandboxStats {
        SandboxStats {
            enabled: self.enabled.load(Ordering::Acquire),
            profile_count: self.profile_count.load(Ordering::Acquire),
            violations: self.violations.load(Ordering::Acquire),
            processes_sandboxed: self.processes_sandboxed.load(Ordering::Acquire),
        }
    }
}

impl Default for SandboxController {
    fn default() -> Self {
        Self::new()
    }
}

/// Sandbox statistics
#[repr(C)]
pub struct SandboxStats {
    pub enabled: bool,
    pub profile_count: u8,
    pub violations: u64,
    pub processes_sandboxed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selinux_context() {
        let mut policy = SelinuxPolicy::new();
        let sid = policy.add_context(0, 0, 1, 0, 3).unwrap();
        assert_eq!(sid, 1);
    }

    #[test]
    fn selinux_permission() {
        let mut policy = SelinuxPolicy::new();
        policy.enable(selinux_mode::ENFORCING);
        
        let src = policy.add_context(0, 0, 1, 0, 3).unwrap();
        let tgt = policy.add_context(0, 0, 2, 0, 3).unwrap();
        
        policy.add_te_rule(1, 2, obj_class::FILE, perm::READ | perm::WRITE, 0).unwrap();
        
        let allowed = policy.check_permission(src, tgt, obj_class::FILE, perm::READ).unwrap();
        assert!(allowed);
    }

    #[test]
    fn seccomp_filter() {
        let mut filter = SeccompFilter::new();
        filter.enable(1);
        
        filter.add_rule(59, seccomp_action::ALLOW, &[0; 6], &[0; 6]).unwrap(); // execve
        
        let action = filter.check_syscall(59, &[0; 6]);
        assert_eq!(action, seccomp_action::ALLOW);
    }

    #[test]
    fn sandbox_profile() {
        let mut ctrl = SandboxController::new();
        ctrl.enable();
        
        let id = ctrl.create_profile(0x12345678).unwrap();
        assert!(ctrl.apply_profile(id).is_ok());
    }
}
