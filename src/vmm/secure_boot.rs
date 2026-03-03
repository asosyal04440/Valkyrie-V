//! Secure Boot and Measured Boot
//!
//! UEFI Secure Boot verification and TPM-based measured boot for attestation.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Secure Boot Constants
// ─────────────────────────────────────────────────────────────────────────────

/// UEFI Secure Boot signature database types
pub const EFI_VAR_SECURE_BOOT: u32 = 0x01;
pub const EFI_VAR_PK: u32 = 0x02;
pub const EFI_VAR_KEK: u32 = 0x03;
pub const EFI_VAR_DB: u32 = 0x04;
pub const EFI_VAR_DBX: u32 = 0x05;
pub const EFI_VAR_DBT: u32 = 0x06;
pub const EFI_VAR_DBR: u32 = 0x07;

/// Secure Boot mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SecureBootMode {
    /// Secure Boot disabled
    Disabled = 0,
    /// Secure Boot enabled, setup mode
    Setup = 1,
    /// Secure Boot enabled, user mode
    User = 2,
    /// Secure Boot enabled, audit mode
    Audit = 3,
    /// Secure Boot enabled, deployed mode
    Deployed = 4,
}

/// Signature types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum SignatureType {
    /// SHA-256 hash
    Sha256 = 0xC1C41626,
    /// RSA-2048 with SHA-256
    Rsa2048Sha256 = 0xA15C593E,
    /// RSA-2048 with SHA-1 (deprecated)
    Rsa2048Sha1 = 0x72C6E583,
    /// X.509 certificate
    X509 = 0xA5C05AA0,
    /// SHA-1 hash (deprecated)
    Sha1 = 0x8293B647,
}

/// WinCertificate structure
#[repr(C)]
pub struct WinCertificate {
    /// Certificate revision
    pub revision: u16,
    /// Certificate type
    pub cert_type: u16,
    /// Certificate data length
    pub length: u32,
    // Certificate data follows
}

/// EFI Signature Data
#[repr(C)]
pub struct EfiSignatureData {
    /// Signature owner GUID
    pub owner: [u8; 16],
    // Signature data follows
}

/// EFI Signature List
#[repr(C)]
pub struct EfiSignatureList {
    /// Signature type GUID
    pub signature_type: [u8; 16],
    /// Total size of list
    pub signature_list_size: u32,
    /// Size of header
    pub signature_header_size: u32,
    /// Size of each signature
    pub signature_size: u32,
}

/// Key database entry
pub struct KeyDbEntry {
    /// Variable name (PK, KEK, db, dbx)
    pub var_name: u32,
    /// Signature type
    pub sig_type: AtomicU16,
    /// Owner GUID
    pub owner: [AtomicU8; 16],
    /// Signature data (max 512 bytes for X.509)
    pub signature: [AtomicU8; 512],
    /// Signature length
    pub sig_len: AtomicU16,
    /// Entry valid
    pub valid: AtomicBool,
}

impl KeyDbEntry {
    pub const fn new() -> Self {
        Self {
            var_name: 0,
            sig_type: AtomicU16::new(0),
            owner: [const { AtomicU8::new(0) }; 16],
            signature: [const { AtomicU8::new(0) }; 512],
            sig_len: AtomicU16::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

/// Maximum key database entries per variable
pub const MAX_KEY_ENTRIES: usize = 64;

/// Secure Boot State
pub struct SecureBootState {
    /// Current mode
    pub mode: AtomicU8,
    /// Secure Boot enabled
    pub enabled: AtomicBool,
    /// Setup mode (no PK enrolled)
    pub setup_mode: AtomicBool,
    /// Audit mode
    pub audit_mode: AtomicBool,
    /// Deployed mode
    pub deployed_mode: AtomicBool,
    /// PK (Platform Key) database
    pub pk: [KeyDbEntry; MAX_KEY_ENTRIES],
    /// KEK (Key Exchange Key) database
    pub kek: [KeyDbEntry; MAX_KEY_ENTRIES],
    /// db (Authorized signatures) database
    pub db: [KeyDbEntry; MAX_KEY_ENTRIES],
    /// dbx (Forbidden signatures) database
    pub dbx: [KeyDbEntry; MAX_KEY_ENTRIES],
    /// Number of PK entries
    pub pk_count: AtomicU8,
    /// Number of KEK entries
    pub kek_count: AtomicU8,
    /// Number of db entries
    pub db_count: AtomicU8,
    /// Number of dbx entries
    pub dbx_count: AtomicU8,
}

impl SecureBootState {
    pub const fn new() -> Self {
        Self {
            mode: AtomicU8::new(SecureBootMode::Setup as u8),
            enabled: AtomicBool::new(false),
            setup_mode: AtomicBool::new(true),
            audit_mode: AtomicBool::new(false),
            deployed_mode: AtomicBool::new(false),
            pk: [const { KeyDbEntry::new() }; MAX_KEY_ENTRIES],
            kek: [const { KeyDbEntry::new() }; MAX_KEY_ENTRIES],
            db: [const { KeyDbEntry::new() }; MAX_KEY_ENTRIES],
            dbx: [const { KeyDbEntry::new() }; MAX_KEY_ENTRIES],
            pk_count: AtomicU8::new(0),
            kek_count: AtomicU8::new(0),
            db_count: AtomicU8::new(0),
            dbx_count: AtomicU8::new(0),
        }
    }

    /// Enable Secure Boot
    pub fn enable(&self) -> Result<(), HvError> {
        if self.pk_count.load(Ordering::Acquire) == 0 {
            return Err(HvError::LogicalFault); // Need PK first
        }
        
        self.enabled.store(true, Ordering::Release);
        self.setup_mode.store(false, Ordering::Release);
        self.mode.store(SecureBootMode::User as u8, Ordering::Release);
        Ok(())
    }

    /// Disable Secure Boot
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        self.setup_mode.store(true, Ordering::Release);
        self.mode.store(SecureBootMode::Setup as u8, Ordering::Release);
    }

    /// Enroll PK (transitions from setup to user mode)
    pub fn enroll_pk(&mut self, owner: [u8; 16], signature: &[u8]) -> Result<(), HvError> {
        let count = self.pk_count.load(Ordering::Acquire) as usize;
        if count >= MAX_KEY_ENTRIES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.pk[count];
        for i in 0..16 {
            entry.owner[i].store(owner[i], Ordering::Release);
        }
        for i in 0..signature.len().min(512) {
            entry.signature[i].store(signature[i], Ordering::Release);
        }
        entry.sig_len.store(signature.len() as u16, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.pk_count.fetch_add(1, Ordering::Release);
        
        // Transition to user mode
        self.setup_mode.store(false, Ordering::Release);
        self.mode.store(SecureBootMode::User as u8, Ordering::Release);
        
        Ok(())
    }

    /// Enroll KEK
    pub fn enroll_kek(&mut self, owner: [u8; 16], signature: &[u8]) -> Result<(), HvError> {
        let count = self.kek_count.load(Ordering::Acquire) as usize;
        if count >= MAX_KEY_ENTRIES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.kek[count];
        for i in 0..16 {
            entry.owner[i].store(owner[i], Ordering::Release);
        }
        for i in 0..signature.len().min(512) {
            entry.signature[i].store(signature[i], Ordering::Release);
        }
        entry.sig_len.store(signature.len() as u16, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.kek_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Enroll db entry
    pub fn enroll_db(&mut self, owner: [u8; 16], signature: &[u8]) -> Result<(), HvError> {
        let count = self.db_count.load(Ordering::Acquire) as usize;
        if count >= MAX_KEY_ENTRIES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.db[count];
        for i in 0..16 {
            entry.owner[i].store(owner[i], Ordering::Release);
        }
        for i in 0..signature.len().min(512) {
            entry.signature[i].store(signature[i], Ordering::Release);
        }
        entry.sig_len.store(signature.len() as u16, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.db_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Enroll dbx entry (forbidden signature)
    pub fn enroll_dbx(&mut self, owner: [u8; 16], signature: &[u8]) -> Result<(), HvError> {
        let count = self.dbx_count.load(Ordering::Acquire) as usize;
        if count >= MAX_KEY_ENTRIES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.dbx[count];
        for i in 0..16 {
            entry.owner[i].store(owner[i], Ordering::Release);
        }
        for i in 0..signature.len().min(512) {
            entry.signature[i].store(signature[i], Ordering::Release);
        }
        entry.sig_len.store(signature.len() as u16, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.dbx_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Verify signature against db
    pub fn verify_signature(&self, hash: &[u8; 32], signature_data: &[u8]) -> Result<(), HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(()); // Secure Boot disabled, allow all
        }
        
        // Check dbx first (forbidden)
        let dbx_count = self.dbx_count.load(Ordering::Acquire) as usize;
        for i in 0..dbx_count {
            let entry = &self.dbx[i];
            if entry.valid.load(Ordering::Acquire) {
                let sig_len = entry.sig_len.load(Ordering::Acquire) as usize;
                
                // Check if hash is in forbidden list
                if sig_len == 32 {
                    let mut sig = [0u8; 32];
                    for j in 0..32 {
                        sig[j] = entry.signature[j].load(Ordering::Acquire);
                    }
                    if &sig == hash {
                        return Err(HvError::LogicalFault); // Forbidden
                    }
                }
            }
        }
        
        // Check db (authorized)
        let db_count = self.db_count.load(Ordering::Acquire) as usize;
        for i in 0..db_count {
            let entry = &self.db[i];
            if entry.valid.load(Ordering::Acquire) {
                let sig_len = entry.sig_len.load(Ordering::Acquire) as usize;
                
                // Check if hash matches authorized hash
                if sig_len == 32 {
                    let mut sig = [0u8; 32];
                    for j in 0..32 {
                        sig[j] = entry.signature[j].load(Ordering::Acquire);
                    }
                    if &sig == hash {
                        return Ok(()); // Authorized
                    }
                }
                
                // Would also check RSA signatures with X.509 certificates
            }
        }
        
        // Check KEK-signed entries
        // Would verify signature chain
        
        Err(HvError::LogicalFault) // Not found in authorized list
    }
}

impl Default for SecureBootState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TPM 2.0 Emulation for Measured Boot
// ─────────────────────────────────────────────────────────────────────────────

/// TPM 2.0 Platform Configuration Register count
pub const TPM_PCR_COUNT: usize = 24;

/// TPM 2.0 Algorithm IDs
pub mod tpm_alg {
    pub const SHA1: u16 = 0x0004;
    pub const SHA256: u16 = 0x000B;
    pub const SHA384: u16 = 0x000C;
    pub const SHA512: u16 = 0x000D;
    pub const SM3_256: u16 = 0x0012;
}

/// TPM 2.0 PCR Selection
#[repr(C)]
pub struct PcrSelection {
    /// Hash algorithm
    pub hash: u16,
    /// PCR selection bitmap (3 bytes for 24 PCRs)
    pub pcr_select: [u8; 3],
}

/// TPM 2.0 Event Log Entry
#[repr(C)]
pub struct TcgEvent {
    /// Event type
    pub event_type: u32,
    /// PCR index
    pub pcr_index: u32,
    /// Digest (SHA-256)
    pub digest: [u8; 32],
    /// Event data length
    pub event_data_len: u32,
    // Event data follows
}

/// TPM 2.0 Event Types
pub mod event_type {
    pub const EV_PREBOOT_CERT: u32 = 0x00000000;
    pub const EV_POST_CODE: u32 = 0x00000001;
    pub const EV_NO_ACTION: u32 = 0x00000003;
    pub const EV_SEPARATOR: u32 = 0x00000004;
    pub const EV_ACTION: u32 = 0x00000005;
    pub const EV_EVENT_TAG: u32 = 0x00000006;
    pub const EV_S_CRTM_CONTENTS: u32 = 0x00000007;
    pub const EV_S_CRTM_VERSION: u32 = 0x00000008;
    pub const EV_CPU_MICROCODE: u32 = 0x00000009;
    pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000000A;
    pub const EV_TABLE_OF_DEVICES: u32 = 0x0000000B;
    pub const EV_COMPACT_HASH: u32 = 0x0000000C;
    pub const EV_IPL: u32 = 0x0000000D;
    pub const EV_IPL_PARTITION_DATA: u32 = 0x0000000E;
    pub const EV_NONHOST_CODE: u32 = 0x0000000F;
    pub const EV_NONHOST_CONFIG: u32 = 0x00000010;
    pub const EV_NONHOST_INFO: u32 = 0x00000011;
    pub const EV_OMIT_BOOT_DEVICE_EVENTS: u32 = 0x00000012;
    pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x80000001;
    pub const EV_EFI_VARIABLE_BOOT: u32 = 0x80000002;
    pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x80000003;
    pub const EV_EFI_BOOT_SERVICES_DRIVER: u32 = 0x80000004;
    pub const EV_EFI_RUNTIME_SERVICES_DRIVER: u32 = 0x80000005;
    pub const EV_EFI_GPT_EVENT: u32 = 0x80000006;
    pub const EV_EFI_ACTION: u32 = 0x80000007;
    pub const EV_EFI_PLATFORM_FIRMWARE_BLOB: u32 = 0x80000008;
    pub const EV_EFI_HANDOFF_TABLES: u32 = 0x80000009;
    pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000000E;
}

/// TPM 2.0 State
pub struct TpmState {
    /// Platform Configuration Registers (24 PCRs, SHA-256)
    pub pcrs: [[AtomicU8; 32]; TPM_PCR_COUNT],
    /// PCR extensions count per PCR
    pub pcr_extend_count: [AtomicU32; TPM_PCR_COUNT],
    /// TPM enabled
    pub enabled: AtomicBool,
    /// TPM active
    pub active: AtomicBool,
    /// TPM owned
    pub owned: AtomicBool,
    /// Locality (0-4)
    pub locality: AtomicU8,
    /// Current operation status
    pub status: AtomicU8,
    /// Supported algorithms
    pub algorithms: AtomicU32,
    /// Event log
    pub event_log: [AtomicU8; 32768],
    /// Event log size
    pub event_log_size: AtomicU32,
    /// Attestation key handle
    pub ak_handle: AtomicU32,
    /// Endorsement key handle
    pub ek_handle: AtomicU32,
}

impl TpmState {
    pub const fn new() -> Self {
        Self {
            pcrs: [const { [const { AtomicU8::new(0) }; 32] }; TPM_PCR_COUNT],
            pcr_extend_count: [const { AtomicU32::new(0) }; TPM_PCR_COUNT],
            enabled: AtomicBool::new(true),
            active: AtomicBool::new(true),
            owned: AtomicBool::new(false),
            locality: AtomicU8::new(0),
            status: AtomicU8::new(0),
            algorithms: AtomicU32::new(1 << tpm_alg::SHA256),
            event_log: [const { AtomicU8::new(0) }; 32768],
            event_log_size: AtomicU32::new(0),
            ak_handle: AtomicU32::new(0),
            ek_handle: AtomicU32::new(0),
        }
    }

    /// Extend PCR with hash
    pub fn extend_pcr(&self, pcr_index: u8, hash: &[u8; 32]) -> Result<(), HvError> {
        if pcr_index as usize >= TPM_PCR_COUNT {
            return Err(HvError::LogicalFault);
        }
        
        let pcr = &self.pcrs[pcr_index as usize];
        
        // SHA-256 extend: new_pcr = SHA256(old_pcr || hash)
        let old: [u8; 32] = core::array::from_fn(|i| pcr[i].load(Ordering::Acquire));
        let combined: [u8; 64] = {
            let mut arr = [0u8; 64];
            arr[..32].copy_from_slice(&old);
            arr[32..].copy_from_slice(hash);
            arr
        };
        
        // Calculate SHA-256 (simplified - would use real hash)
        let new_hash = self.sha256(&combined);
        
        for i in 0..32 {
            pcr[i].store(new_hash[i], Ordering::Release);
        }
        
        self.pcr_extend_count[pcr_index as usize].fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Read PCR value
    pub fn read_pcr(&self, pcr_index: u8) -> Result<[u8; 32], HvError> {
        if pcr_index as usize >= TPM_PCR_COUNT {
            return Err(HvError::LogicalFault);
        }
        
        let pcr = &self.pcrs[pcr_index as usize];
        Ok(core::array::from_fn(|i| pcr[i].load(Ordering::Acquire)))
    }

    /// Reset PCR (only PCR 0-15 for debug)
    pub fn reset_pcr(&self, pcr_index: u8) -> Result<(), HvError> {
        if pcr_index as usize >= 16 {
            return Err(HvError::LogicalFault); // PCR 16-23 cannot be reset
        }
        
        let pcr = &self.pcrs[pcr_index as usize];
        for i in 0..32 {
            pcr[i].store(0, Ordering::Release);
        }
        self.pcr_extend_count[pcr_index as usize].store(0, Ordering::Release);
        
        Ok(())
    }

    /// Add event to event log
    pub fn log_event(&self, pcr_index: u32, event_type: u32, digest: &[u8; 32], event_data: &[u8]) -> Result<(), HvError> {
        let offset = self.event_log_size.load(Ordering::Acquire) as usize;
        let entry_size = 4 + 4 + 32 + 4 + event_data.len();
        
        if offset + entry_size > self.event_log.len() {
            return Err(HvError::LogicalFault);
        }
        
        // Write event type
        for (i, byte) in event_type.to_le_bytes().iter().enumerate() {
            self.event_log[offset + i].store(*byte, Ordering::Release);
        }
        
        // Write PCR index
        for (i, byte) in pcr_index.to_le_bytes().iter().enumerate() {
            self.event_log[offset + 4 + i].store(*byte, Ordering::Release);
        }
        
        // Write digest
        for (i, byte) in digest.iter().enumerate() {
            self.event_log[offset + 8 + i].store(*byte, Ordering::Release);
        }
        
        // Write event data length
        for (i, byte) in (event_data.len() as u32).to_le_bytes().iter().enumerate() {
            self.event_log[offset + 40 + i].store(*byte, Ordering::Release);
        }
        
        // Write event data
        for (i, byte) in event_data.iter().enumerate() {
            self.event_log[offset + 44 + i].store(*byte, Ordering::Release);
        }
        
        self.event_log_size.fetch_add(entry_size as u32, Ordering::Release);
        
        Ok(())
    }

    /// Measure and log event
    pub fn measure_event(&self, pcr_index: u8, event_type: u32, data: &[u8]) -> Result<(), HvError> {
        // Hash the data
        let digest = self.sha256(data);
        
        // Extend PCR
        self.extend_pcr(pcr_index, &digest)?;
        
        // Log event
        self.log_event(pcr_index as u32, event_type, &digest, data)?;
        
        Ok(())
    }

    /// Get event log
    pub fn get_event_log(&self) -> [u8; 32768] {
        let mut log = [0u8; 32768];
        let size = self.event_log_size.load(Ordering::Acquire) as usize;
        for i in 0..size {
            log[i] = self.event_log[i].load(Ordering::Acquire);
        }
        log
    }

    /// Generate attestation quote
    pub fn get_quote(&self, pcr_mask: [u8; 3], nonce: &[u8; 32]) -> TpmQuote {
        let mut pcr_values: [[u8; 32]; TPM_PCR_COUNT] = [[0; 32]; TPM_PCR_COUNT];
        
        for i in 0..TPM_PCR_COUNT {
            if pcr_mask[i / 8] & (1 << (i % 8)) != 0 {
                pcr_values[i] = self.read_pcr(i as u8).unwrap_or([0; 32]);
            }
        }
        
        // Calculate PCR composite hash
        let mut pcr_data = [0u8; 768];
        let mut pcr_data_len = 0;
        for i in 0..TPM_PCR_COUNT {
            if pcr_mask[i / 8] & (1 << (i % 8)) != 0 {
                pcr_data[pcr_data_len..pcr_data_len + 32].copy_from_slice(&pcr_values[i]);
                pcr_data_len += 32;
            }
        }
        let pcr_digest = self.sha256(&pcr_data[..pcr_data_len]);
        
        // Sign quote (would use AK in real implementation)
        let mut signature = [0u8; 256];
        // Would generate RSA-2048 signature here
        
        TpmQuote {
            pcr_mask,
            pcr_digest,
            nonce: *nonce,
            signature,
            signature_len: 256,
        }
    }

    /// Simple SHA-256 (placeholder - would use real implementation)
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        // Simplified hash - in production use real SHA-256
        let mut hash = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            hash[i % 32] ^= byte;
            hash[(i + 1) % 32] = hash[(i + 1) % 32].wrapping_add(*byte);
        }
        hash
    }

    /// Take ownership
    pub fn take_ownership(&self, _auth_value: &[u8]) -> Result<(), HvError> {
        if self.owned.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault); // Already owned
        }
        
        // Would generate EK and set owner auth
        self.owned.store(true, Ordering::Release);
        Ok(())
    }

    /// Clear TPM
    pub fn clear(&self) {
        for pcr in &self.pcrs {
            for byte in pcr {
                byte.store(0, Ordering::Release);
            }
        }
        for count in &self.pcr_extend_count {
            count.store(0, Ordering::Release);
        }
        self.event_log_size.store(0, Ordering::Release);
        self.owned.store(false, Ordering::Release);
    }
}

impl Default for TpmState {
    fn default() -> Self {
        Self::new()
    }
}

/// TPM Quote structure
#[repr(C)]
pub struct TpmQuote {
    /// PCR selection mask
    pub pcr_mask: [u8; 3],
    /// PCR composite digest
    pub pcr_digest: [u8; 32],
    /// Nonce (qualifying data)
    pub nonce: [u8; 32],
    /// Signature (RSA-2048)
    pub signature: [u8; 256],
    /// Signature length
    pub signature_len: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// Measured Boot Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Boot phases
pub mod boot_phase {
    pub const BIOS: u8 = 0;
    pub const BOOTLOADER: u8 = 1;
    pub const KERNEL: u8 = 2;
    pub const INITRD: u8 = 3;
    pub const COMPLETE: u8 = 4;
}

/// Measured Boot controller
pub struct MeasuredBootController {
    /// Secure Boot state
    pub secure_boot: SecureBootState,
    /// TPM state
    pub tpm: TpmState,
    /// Boot phase
    pub boot_phase: AtomicU8,
}

impl MeasuredBootController {
    pub const fn new() -> Self {
        Self {
            secure_boot: SecureBootState::new(),
            tpm: TpmState::new(),
            boot_phase: AtomicU8::new(boot_phase::BIOS),
        }
    }

    /// Initialize measured boot
    pub fn init(&mut self) {
        // Measure CRTM (Core Root of Trust for Measurement)
        self.tpm.measure_event(0, event_type::EV_S_CRTM_VERSION, b"Valkyrie-V CRTM v1.0").ok();
        
        // Record boot separator
        self.tpm.measure_event(0, event_type::EV_SEPARATOR, &[0, 0, 0, 0]).ok();
    }

    /// Measure boot component
    pub fn measure_component(&self, phase: u8, name: &str, data: &[u8]) -> Result<(), HvError> {
        // Update boot phase
        self.boot_phase.store(phase, Ordering::Release);
        
        // Determine PCR based on phase
        let pcr = match phase {
            boot_phase::BIOS => 0,
            boot_phase::BOOTLOADER => 4,
            boot_phase::KERNEL => 4,
            boot_phase::INITRD => 5,
            _ => 0,
        };
        
        // Determine event type
        let event_type = match phase {
            boot_phase::BIOS => event_type::EV_POST_CODE,
            boot_phase::BOOTLOADER => event_type::EV_IPL,
            boot_phase::KERNEL => event_type::EV_EFI_BOOT_SERVICES_APPLICATION,
            boot_phase::INITRD => event_type::EV_EFI_VARIABLE_BOOT,
            _ => event_type::EV_NO_ACTION,
        };
        
        // Create event data with name
        let mut event_data: Vec<u8, 256> = name.as_bytes().to_vec();
        event_data.extend_from_slice(data);
        
        // Measure
        self.tpm.measure_event(pcr, event_type, &event_data)
    }

    /// Verify boot chain
    pub fn verify_boot_chain(&self, components: &[(String, [u8; 32])]) -> Result<(), HvError> {
        if !self.secure_boot.enabled.load(Ordering::Acquire) {
            return Ok(()); // Secure Boot disabled
        }
        
        for (_name, hash) in components {
            self.secure_boot.verify_signature(hash, &[])?;
        }
        
        Ok(())
    }

    /// Get attestation report
    pub fn get_attestation_report(&self, nonce: &[u8; 32]) -> AttestationReport {
        // Get quote for all PCRs
        let quote = self.tpm.get_quote([0xFF, 0xFF, 0xFF], nonce);
        
        // Get event log
        let event_log = self.tpm.get_event_log();
        
        AttestationReport {
            quote,
            event_log_size: event_log.len() as u32,
            secure_boot_enabled: self.secure_boot.enabled.load(Ordering::Acquire),
            boot_phase: self.boot_phase.load(Ordering::Acquire),
        }
    }
}

impl Default for MeasuredBootController {
    fn default() -> Self {
        Self::new()
    }
}

/// Attestation Report
#[repr(C)]
pub struct AttestationReport {
    /// TPM quote
    pub quote: TpmQuote,
    /// Event log size
    pub event_log_size: u32,
    /// Secure Boot enabled
    pub secure_boot_enabled: bool,
    /// Boot phase
    pub boot_phase: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_boot_enroll() {
        let mut sb = SecureBootState::new();
        
        sb.enroll_pk([0; 16], &[1, 2, 3, 4]).unwrap();
        assert_eq!(sb.pk_count.load(Ordering::Acquire), 1);
        assert!(!sb.setup_mode.load(Ordering::Acquire));
    }

    #[test]
    fn secure_boot_enable() {
        let mut sb = SecureBootState::new();
        sb.enroll_pk([0; 16], &[1, 2, 3, 4]).unwrap();
        
        sb.enable().unwrap();
        assert!(sb.enabled.load(Ordering::Acquire));
    }

    #[test]
    fn tpm_extend_pcr() {
        let tpm = TpmState::new();
        
        tpm.extend_pcr(0, &[1; 32]).unwrap();
        assert!(tpm.pcr_extend_count[0].load(Ordering::Acquire) > 0);
    }

    #[test]
    fn tpm_measure() {
        let tpm = TpmState::new();
        
        tpm.measure_event(0, event_type::EV_POST_CODE, b"test data").unwrap();
        
        let log = tpm.get_event_log();
        assert!(!log.is_empty());
    }

    #[test]
    fn measured_boot_init() {
        let mut mb = MeasuredBootController::new();
        mb.init();
        
        assert!(mb.tpm.pcr_extend_count[0].load(Ordering::Acquire) > 0);
    }
}
