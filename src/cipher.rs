//! AEAD cipher abstraction for NTS-protected NTP.
//!
//! Provides [`AeadCipher`], an internal enum that wraps AES-SIV-CMAC-256 and
//! AES-SIV-CMAC-512 as defined in RFC 5297 and required by RFC 8915.

use aes_siv::{KeyInit, siv::Aes128Siv, siv::Aes256Siv};

use crate::error::{Error, Result};

/// AEAD algorithm IDs as defined in RFC 8915 §7.1.
pub(crate) const AEAD_AES_SIV_CMAC_256: u16 = 15;
pub(crate) const AEAD_AES_SIV_CMAC_512: u16 = 17;

/// AES-SIV-CMAC cipher for NTS authenticated encryption.
///
/// Supports AEAD_AES_SIV_CMAC_256 (32-byte key) and AEAD_AES_SIV_CMAC_512
/// (64-byte key) as specified in RFC 8915 §4 and RFC 5297.
///
/// Both `encrypt_siv` and `decrypt_siv` accept multiple associated-data
/// components (`ad: &[&[u8]]`), which map directly to the multi-component
/// S2V function defined in RFC 5297 §2.4.
pub(crate) enum AeadCipher {
    /// AEAD_AES_SIV_CMAC_256 — AES-SIV with a 32-byte key.
    SivCmac256(Box<[u8; 32]>),
    /// AEAD_AES_SIV_CMAC_512 — AES-SIV with a 64-byte key.
    SivCmac512(Box<[u8; 64]>),
}

impl AeadCipher {
    /// Construct an [`AeadCipher`] from a raw key slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyExchange`] if `alg_id` is unsupported or `key`
    /// does not have the correct length for the algorithm.
    pub(crate) fn from_key_bytes(alg_id: u16, key: &[u8]) -> Result<Self> {
        match alg_id {
            AEAD_AES_SIV_CMAC_256 => {
                let bytes: [u8; 32] = key.try_into().map_err(|_| {
                    Error::KeyExchange(format!(
                        "AEAD_AES_SIV_CMAC_256 requires a 32-byte key, got {} bytes",
                        key.len()
                    ))
                })?;
                Ok(AeadCipher::SivCmac256(Box::new(bytes)))
            }
            AEAD_AES_SIV_CMAC_512 => {
                let bytes: [u8; 64] = key.try_into().map_err(|_| {
                    Error::KeyExchange(format!(
                        "AEAD_AES_SIV_CMAC_512 requires a 64-byte key, got {} bytes",
                        key.len()
                    ))
                })?;
                Ok(AeadCipher::SivCmac512(Box::new(bytes)))
            }
            _ => Err(Error::KeyExchange(format!(
                "Unsupported AEAD algorithm ID: {}",
                alg_id
            ))),
        }
    }

    /// Returns the required key length in bytes for the given algorithm ID,
    /// or `None` if the algorithm is not supported.
    pub(crate) fn key_len(alg_id: u16) -> Option<usize> {
        match alg_id {
            AEAD_AES_SIV_CMAC_256 => Some(32),
            AEAD_AES_SIV_CMAC_512 => Some(64),
            _ => None,
        }
    }

    /// Encrypt `plaintext` with the provided associated-data components.
    ///
    /// Returns the SIV tag prepended to the encrypted ciphertext. For an
    /// empty plaintext the return value is exactly 16 bytes (the SIV tag
    /// only), which is the format used for client NTP requests.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AeadVerificationFailed`] if the underlying AES-SIV
    /// operation fails (should not occur for well-formed inputs).
    pub(crate) fn encrypt_siv(&self, ad: &[&[u8]], plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::SivCmac256(key) => {
                let mut siv = Aes128Siv::new_from_slice(key.as_ref())
                    .expect("key length is validated at construction");
                siv.encrypt(ad, plaintext).map_err(|_| {
                    Error::AeadVerificationFailed("AES-SIV-256 encrypt failed".to_string())
                })
            }
            AeadCipher::SivCmac512(key) => {
                let mut siv = Aes256Siv::new_from_slice(key.as_ref())
                    .expect("key length is validated at construction");
                siv.encrypt(ad, plaintext).map_err(|_| {
                    Error::AeadVerificationFailed("AES-SIV-512 encrypt failed".to_string())
                })
            }
        }
    }

    /// Decrypt and authenticate `ciphertext` with the provided
    /// associated-data components.
    ///
    /// The `ciphertext` must be the value returned by [`AeadCipher::encrypt_siv`]:
    /// a 16-byte SIV tag followed by the encrypted payload.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AeadVerificationFailed`] if authentication fails,
    /// indicating that the data has been tampered with or the wrong key
    /// or associated data was used.
    pub(crate) fn decrypt_siv(&self, ad: &[&[u8]], ciphertext: &[u8]) -> Result<Vec<u8>> {
        match self {
            AeadCipher::SivCmac256(key) => {
                let mut siv = Aes128Siv::new_from_slice(key.as_ref())
                    .expect("key length is validated at construction");
                siv.decrypt(ad, ciphertext).map_err(|_| {
                    Error::AeadVerificationFailed(
                        "AES-SIV-256 authentication failed".to_string(),
                    )
                })
            }
            AeadCipher::SivCmac512(key) => {
                let mut siv = Aes256Siv::new_from_slice(key.as_ref())
                    .expect("key length is validated at construction");
                siv.decrypt(ad, ciphertext).map_err(|_| {
                    Error::AeadVerificationFailed(
                        "AES-SIV-512 authentication failed".to_string(),
                    )
                })
            }
        }
    }
}

impl std::fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadCipher::SivCmac256(_) => write!(f, "SivCmac256([redacted])"),
            AeadCipher::SivCmac512(_) => write!(f, "SivCmac512([redacted])"),
        }
    }
}

impl Drop for AeadCipher {
    fn drop(&mut self) {
        match self {
            AeadCipher::SivCmac256(key) => key.iter_mut().for_each(|b| *b = 0),
            AeadCipher::SivCmac512(key) => key.iter_mut().for_each(|b| *b = 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmac256_roundtrip() {
        let key = [0u8; 32];
        let cipher = AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_256, &key).unwrap();
        let ad0 = b"ntp header bytes";
        let ad1 = b"nonce";
        let plaintext = b"cookie payload";
        let ct = cipher.encrypt_siv(&[ad0, ad1], plaintext).unwrap();
        let pt = cipher.decrypt_siv(&[ad0, ad1], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_cmac512_roundtrip() {
        let key = [0u8; 64];
        let cipher = AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_512, &key).unwrap();
        let ad0 = b"header";
        let ad1 = b"nonce16byteshere";
        let plaintext = b"another cookie";
        let ct = cipher.encrypt_siv(&[ad0, ad1], plaintext).unwrap();
        let pt = cipher.decrypt_siv(&[ad0, ad1], &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_auth_only_empty_plaintext() {
        // Client NTP requests encrypt empty plaintext — result is only the 16-byte SIV tag.
        let key = [1u8; 32];
        let cipher = AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_256, &key).unwrap();
        let ct = cipher.encrypt_siv(&[b"aad"], &[]).unwrap();
        assert_eq!(ct.len(), 16, "SIV tag must be exactly 16 bytes for empty plaintext");
        let pt = cipher.decrypt_siv(&[b"aad"], &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn test_tampered_ciphertext_is_rejected() {
        let key = [2u8; 32];
        let cipher = AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_256, &key).unwrap();
        let mut ct = cipher.encrypt_siv(&[b"aad"], b"secret").unwrap();
        ct[0] ^= 0xff;
        assert!(cipher.decrypt_siv(&[b"aad"], &ct).is_err());
    }

    #[test]
    fn test_wrong_aad_is_rejected() {
        let key = [3u8; 32];
        let cipher = AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_256, &key).unwrap();
        let ct = cipher.encrypt_siv(&[b"correct"], b"data").unwrap();
        assert!(cipher.decrypt_siv(&[b"wrong"], &ct).is_err());
    }

    #[test]
    fn test_invalid_key_length_is_error() {
        // alg 15 expects 32-byte key
        assert!(AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_256, &[0u8; 16]).is_err());
        // alg 17 expects 64-byte key
        assert!(AeadCipher::from_key_bytes(AEAD_AES_SIV_CMAC_512, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_unknown_algorithm_is_error() {
        assert!(AeadCipher::from_key_bytes(0, &[0u8; 32]).is_err());
        assert!(AeadCipher::from_key_bytes(99, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_key_len() {
        assert_eq!(AeadCipher::key_len(AEAD_AES_SIV_CMAC_256), Some(32));
        assert_eq!(AeadCipher::key_len(AEAD_AES_SIV_CMAC_512), Some(64));
        assert_eq!(AeadCipher::key_len(0), None);
    }
}
