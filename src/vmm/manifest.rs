#![allow(clippy::new_without_default)]

use crate::vmm::{DriverTag, HvError};
use ironshim::crypto::Sha256;
use ironshim::{ManifestSignature, ManifestValidator, ResourceManifest, RevocationList};

const MAX_TRUSTED: usize = 4;
const MAX_REVOKED: usize = 8;
const MAX_SIGNATURE_SKEW: u64 = 5;

pub struct TrustedKey {
    pub key_id: u64,
    pub prev_id: u64,
    pub expires_at: u64,
    pub key: [u8; 32],
}

pub struct SignatureRecord {
    pub key_id: u64,
    pub prev_id: u64,
    pub issued: u64,
    pub expires: u64,
    pub sig: [u8; 32],
}

pub struct ManifestAuthority {
    trusted: [TrustedKey; MAX_TRUSTED],
    revoked: [u64; MAX_REVOKED],
}

impl ManifestAuthority {
    pub const fn new() -> Self {
        Self {
            trusted: [
                TrustedKey {
                    key_id: 1,
                    prev_id: 0,
                    expires_at: 0,
                    key: [0x42; 32],
                },
                TrustedKey {
                    key_id: 0,
                    prev_id: 0,
                    expires_at: 0,
                    key: [0; 32],
                },
                TrustedKey {
                    key_id: 0,
                    prev_id: 0,
                    expires_at: 0,
                    key: [0; 32],
                },
                TrustedKey {
                    key_id: 0,
                    prev_id: 0,
                    expires_at: 0,
                    key: [0; 32],
                },
            ],
            revoked: [0; MAX_REVOKED],
        }
    }

    pub fn sign<const M: usize, const P: usize>(
        &self,
        manifest: &ResourceManifest<DriverTag, M, P>,
        key_id: u64,
        issued: u64,
        expires: u64,
    ) -> Result<SignatureRecord, HvError> {
        let key = self.key_by_id(key_id).ok_or(HvError::LogicalFault)?;
        let hash = manifest.compute_hash();
        let payload = build_payload(&hash, key_id, key.prev_id, issued, expires);
        let sig = hmac_sha256(&key.key, payload.as_slice());
        Ok(SignatureRecord {
            key_id,
            prev_id: key.prev_id,
            issued,
            expires,
            sig,
        })
    }

    pub fn rotate_key(
        &mut self,
        key_id: u64,
        key: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), HvError> {
        if key_id == 0 || self.key_by_id(key_id).is_some() {
            return Err(HvError::LogicalFault);
        }
        let prev_id = self.active_key_id(now).unwrap_or(0);
        let new_key = TrustedKey {
            key_id,
            prev_id,
            expires_at,
            key,
        };
        self.insert_key(new_key, now)?;
        if prev_id != 0 {
            self.revoke_key(prev_id)?;
        }
        Ok(())
    }

    pub fn update_revocations(&mut self, keys: &[u64]) -> Result<(), HvError> {
        for &key_id in keys {
            if key_id == 0 {
                continue;
            }
            self.revoke_key(key_id)?;
        }
        Ok(())
    }

    pub fn validate<const M: usize, const P: usize>(
        &self,
        manifest: &ResourceManifest<DriverTag, M, P>,
        record: &SignatureRecord,
        now: u64,
    ) -> Result<(), HvError> {
        let signature = ManifestSignature {
            key_id: record.key_id,
            timestamp: record.issued,
            hash: manifest.compute_hash(),
        };
        let validator = HmacValidator {
            authority: self,
            record,
            hash: signature.hash,
            now,
        };
        let revoked = RevokedKeys { authority: self };
        manifest
            .validate_signature(&signature, &validator, &revoked)
            .map_err(|_| HvError::LogicalFault)
    }

    fn key_by_id(&self, key_id: u64) -> Option<&TrustedKey> {
        self.trusted
            .iter()
            .find(|key| key.key_id == key_id && key.key_id != 0)
    }

    fn active_key_id(&self, now: u64) -> Option<u64> {
        let mut best = None;
        for key in self.trusted.iter() {
            if key.key_id == 0 {
                continue;
            }
            if key.expires_at != 0 && key.expires_at < now {
                continue;
            }
            if self.is_revoked(key.key_id) {
                continue;
            }
            best = match best {
                Some(existing) if existing >= key.key_id => Some(existing),
                _ => Some(key.key_id),
            };
        }
        best
    }

    fn insert_key(&mut self, key: TrustedKey, now: u64) -> Result<(), HvError> {
        if let Some(slot) = self.trusted.iter_mut().find(|slot| slot.key_id == 0) {
            *slot = key;
            return Ok(());
        }
        if let Some(slot) = self
            .trusted
            .iter_mut()
            .find(|slot| slot.expires_at != 0 && slot.expires_at < now)
        {
            *slot = key;
            return Ok(());
        }
        Err(HvError::LogicalFault)
    }

    fn revoke_key(&mut self, key_id: u64) -> Result<(), HvError> {
        if self.is_revoked(key_id) || key_id == 0 {
            return Ok(());
        }
        if let Some(slot) = self.revoked.iter_mut().find(|slot| **slot == 0) {
            *slot = key_id;
            return Ok(());
        }
        for index in 1..MAX_REVOKED {
            self.revoked[index - 1] = self.revoked[index];
        }
        self.revoked[MAX_REVOKED - 1] = key_id;
        Ok(())
    }

    fn is_revoked(&self, key_id: u64) -> bool {
        self.revoked.iter().any(|id| *id == key_id && *id != 0)
    }

    fn validate_chain(&self, key_id: u64, now: u64) -> Result<(), HvError> {
        let mut current = key_id;
        for _ in 0..8 {
            let Some(key) = self.key_by_id(current) else {
                return Err(HvError::LogicalFault);
            };
            if self.is_revoked(key.key_id) {
                return Err(HvError::LogicalFault);
            }
            if key.expires_at != 0 && key.expires_at < now {
                return Err(HvError::LogicalFault);
            }
            if key.prev_id == 0 {
                return Ok(());
            }
            current = key.prev_id;
        }
        Err(HvError::LogicalFault)
    }
}

struct HmacValidator<'a> {
    authority: &'a ManifestAuthority,
    record: &'a SignatureRecord,
    hash: [u8; 32],
    now: u64,
}

impl<'a> ManifestValidator for HmacValidator<'a> {
    fn validate(&self, signature: &ManifestSignature) -> Result<(), ironshim::Error> {
        if signature.key_id != self.record.key_id {
            return Err(ironshim::Error::SignatureInvalid);
        }
        if signature.hash != self.hash {
            return Err(ironshim::Error::SignatureInvalid);
        }
        if self.record.issued > self.now.saturating_add(MAX_SIGNATURE_SKEW) {
            return Err(ironshim::Error::SignatureInvalid);
        }
        if self.record.expires != 0 && self.record.expires < self.record.issued {
            return Err(ironshim::Error::SignatureInvalid);
        }
        if self.record.expires != 0 && self.record.expires < self.now {
            return Err(ironshim::Error::SignatureInvalid);
        }
        self.authority
            .validate_chain(self.record.key_id, self.now)
            .map_err(|_| ironshim::Error::SignatureInvalid)?;
        let key = self
            .authority
            .key_by_id(self.record.key_id)
            .ok_or(ironshim::Error::SignatureInvalid)?;
        let payload = build_payload(
            &self.hash,
            self.record.key_id,
            self.record.prev_id,
            self.record.issued,
            self.record.expires,
        );
        let expected = hmac_sha256(&key.key, payload.as_slice());
        if expected != self.record.sig {
            return Err(ironshim::Error::SignatureInvalid);
        }
        Ok(())
    }
}

struct RevokedKeys<'a> {
    authority: &'a ManifestAuthority,
}

impl<'a> RevocationList for RevokedKeys<'a> {
    fn is_revoked(&self, key_id: u64) -> bool {
        self.authority.is_revoked(key_id)
    }
}

struct Payload {
    bytes: [u8; 256],
    len: usize,
}

impl Payload {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn build_payload(hash: &[u8; 32], key_id: u64, prev_id: u64, issued: u64, expires: u64) -> Payload {
    let mut out = [0u8; 256];
    let mut cursor = 0usize;
    cursor = write_bytes(&mut out, cursor, b"v=2\nhash=");
    cursor = write_hex(&mut out, cursor, hash);
    cursor = write_bytes(&mut out, cursor, b"\nkey_id=");
    cursor = write_u64(&mut out, cursor, key_id);
    cursor = write_bytes(&mut out, cursor, b"\nprev_id=");
    if prev_id == 0 {
        cursor = write_bytes(&mut out, cursor, b"none");
    } else {
        cursor = write_u64(&mut out, cursor, prev_id);
    }
    cursor = write_bytes(&mut out, cursor, b"\nissued=");
    cursor = write_u64(&mut out, cursor, issued);
    cursor = write_bytes(&mut out, cursor, b"\nexpires=");
    cursor = write_u64(&mut out, cursor, expires);
    cursor = write_bytes(&mut out, cursor, b"\n");
    Payload {
        bytes: out,
        len: cursor,
    }
}

fn write_bytes(buffer: &mut [u8; 256], mut cursor: usize, bytes: &[u8]) -> usize {
    for &b in bytes {
        if cursor >= buffer.len() {
            break;
        }
        buffer[cursor] = b;
        cursor += 1;
    }
    cursor
}

fn write_hex(buffer: &mut [u8; 256], mut cursor: usize, hash: &[u8; 32]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in hash.iter() {
        if cursor + 1 >= buffer.len() {
            break;
        }
        buffer[cursor] = HEX[(b >> 4) as usize];
        buffer[cursor + 1] = HEX[(b & 0xF) as usize];
        cursor += 2;
    }
    cursor
}

fn write_u64(buffer: &mut [u8; 256], mut cursor: usize, mut value: u64) -> usize {
    let mut digits = [0u8; 20];
    let mut len = 0usize;
    if value == 0 {
        return write_bytes(buffer, cursor, b"0");
    }
    while value > 0 && len < digits.len() {
        digits[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        if cursor >= buffer.len() {
            break;
        }
        buffer[cursor] = digits[len];
        cursor += 1;
    }
    cursor
}

pub(crate) fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = sha256_concat(&ipad, data);
    sha256_concat(&opad, &inner)
}

fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironshim::parse_manifest_blob;

    #[test]
    fn fuzz_manifest_parse_verify() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let authority = ManifestAuthority::new();
        for len in 4usize..96 {
            let mut bytes = vec![0u8; len];
            for slot in bytes.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *slot = (seed >> 32) as u8;
            }
            if let Ok(manifest) = parse_manifest_blob::<DriverTag, 4, 4>(&bytes) {
                let record = authority.sign(&manifest, 1, 1, 2).unwrap();
                assert!(authority.validate(&manifest, &record, 1).is_ok());
            }
        }
    }
}
