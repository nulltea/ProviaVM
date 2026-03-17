#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
pub use jolt_inlines_rsa::{Bytes2048, Step2048, Witness2048};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Pre-parsed DKIM verification input.
/// The host extracts these from the raw email + DNS lookup.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DKIMInput {
    /// Canonicalized DKIM-signed header bytes (the data that was signed)
    pub signed_headers: Vec<u8>,
    /// RSA signature bytes (base64-decoded from b= tag)
    pub signature: Vec<u8>,
    /// RSA public key in PKCS#1 DER format, from DNS TXT record
    pub public_key_der: Vec<u8>,
    /// Sender domain as bytes (e.g., b"google.com")
    pub from_domain: Vec<u8>,
    /// Transcript-bound seed for RSA witness compression checks.
    pub rsa_challenge_seed: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct DKIMInputRef<'a> {
    pub signed_headers: &'a [u8],
    pub signature: Bytes2048,
    pub public_key_der: &'a [u8],
    pub from_domain: &'a [u8],
    pub rsa_challenge_seed: [u8; 32],
}

const DKIM_INPUT_REF_HEADER_LEN: usize = 3 * 4 + 32 + 256;

impl<'a> DKIMInputRef<'a> {
    fn pack_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            DKIM_INPUT_REF_HEADER_LEN + self.signed_headers.len() + self.public_key_der.len() + self.from_domain.len(),
        );
        payload.extend_from_slice(&(self.signed_headers.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(self.public_key_der.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(self.from_domain.len() as u32).to_le_bytes());
        payload.extend_from_slice(&self.rsa_challenge_seed);
        payload.extend_from_slice(&self.signature.0);
        payload.extend_from_slice(self.signed_headers);
        payload.extend_from_slice(self.public_key_der);
        payload.extend_from_slice(self.from_domain);
        payload
    }

    fn parse_packed(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < DKIM_INPUT_REF_HEADER_LEN {
            return Err("packed DKIM input too short");
        }

        let signed_headers_len = read_len(bytes, 0)?;
        let public_key_der_len = read_len(bytes, 4)?;
        let from_domain_len = read_len(bytes, 8)?;

        let mut signature = [0u8; 256];
        signature.copy_from_slice(&bytes[44..300]);

        let mut cursor = DKIM_INPUT_REF_HEADER_LEN;
        let signed_headers = take_packed_slice(bytes, &mut cursor, signed_headers_len)?;
        let public_key_der = take_packed_slice(bytes, &mut cursor, public_key_der_len)?;
        let from_domain = take_packed_slice(bytes, &mut cursor, from_domain_len)?;

        if cursor != bytes.len() {
            return Err("packed DKIM input has trailing bytes");
        }

        let mut rsa_challenge_seed = [0u8; 32];
        rsa_challenge_seed.copy_from_slice(&bytes[12..44]);

        Ok(Self { signed_headers, signature: Bytes2048(signature), public_key_der, from_domain, rsa_challenge_seed })
    }
}

impl Serialize for DKIMInputRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.pack_payload())
    }
}

impl<'de> Deserialize<'de> for DKIMInputRef<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DKIMInputRefVisitor;

        impl<'de> Visitor<'de> for DKIMInputRefVisitor {
            type Value = DKIMInputRef<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("packed DKIM input bytes")
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                DKIMInputRef::parse_packed(value).map_err(E::custom)
            }

            fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let leaked: &'de [u8] = Box::leak(_value.to_vec().into_boxed_slice());
                DKIMInputRef::parse_packed(leaked).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let leaked: &'de [u8] = Box::leak(value.into_boxed_slice());
                DKIMInputRef::parse_packed(leaked).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(DKIMInputRefVisitor)
    }
}

impl DKIMInput {
    pub fn as_ref(&self) -> Result<DKIMInputRef<'_>, &'static str> {
        let signature: [u8; 256] = self.signature.as_slice().try_into().map_err(|_| "signature must be 256 bytes")?;
        Ok(DKIMInputRef {
            signed_headers: &self.signed_headers,
            signature: Bytes2048(signature),
            public_key_der: &self.public_key_der,
            from_domain: &self.from_domain,
            rsa_challenge_seed: self.rsa_challenge_seed,
        })
    }
}

fn read_len(bytes: &[u8], start: usize) -> Result<usize, &'static str> {
    let end = start.checked_add(4).ok_or("packed input length overflow")?;
    let raw = bytes.get(start..end).ok_or("packed input header truncated")?;
    let len = u32::from_le_bytes(raw.try_into().unwrap());
    Ok(len as usize)
}

fn take_packed_slice<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], &'static str> {
    let end = cursor.checked_add(len).ok_or("packed input length overflow")?;
    let slice = bytes.get(*cursor..end).ok_or("packed input truncated")?;
    *cursor = end;
    Ok(slice)
}

/// Output committed by the guest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DKIMOutput {
    /// SHA-256 hash of from_domain
    pub from_domain_hash: [u8; 32],
    /// SHA-256 hash of the public key DER bytes
    pub public_key_hash: [u8; 32],
    /// Whether the DKIM signature verified
    pub verified: bool,
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;

    use super::*;

    #[test]
    fn dkim_input_as_ref_normalizes_signature() {
        let input = DKIMInput {
            signed_headers: b"from:test@example.com".to_vec(),
            signature: vec![0x55; 256],
            public_key_der: vec![0x30, 0x82, 0x01],
            from_domain: b"example.com".to_vec(),
            rsa_challenge_seed: [7u8; 32],
        };

        let input_ref = input.as_ref().unwrap();
        assert_eq!(input_ref.signed_headers, input.signed_headers.as_slice());
        assert_eq!(input_ref.public_key_der, input.public_key_der.as_slice());
        assert_eq!(input_ref.from_domain, input.from_domain.as_slice());
        assert_eq!(input_ref.signature.0, [0x55; 256]);
        assert_eq!(input_ref.rsa_challenge_seed, input.rsa_challenge_seed);
    }

    #[test]
    fn dkim_input_ref_postcard_roundtrip() {
        let input = DKIMInputRef {
            signed_headers: b"from:test@example.com",
            signature: Bytes2048([0x11; 256]),
            public_key_der: b"\x30\x82\x01",
            from_domain: b"example.com",
            rsa_challenge_seed: [9u8; 32],
        };

        let encoded = postcard::to_allocvec(&input).unwrap();
        let decoded: DKIMInputRef<'_> = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.signed_headers, input.signed_headers);
        assert_eq!(decoded.signature, input.signature);
        assert_eq!(decoded.public_key_der, input.public_key_der);
        assert_eq!(decoded.from_domain, input.from_domain);
        assert_eq!(decoded.rsa_challenge_seed, input.rsa_challenge_seed);
    }

    #[test]
    fn dkim_input_as_ref_rejects_short_signature() {
        let input = DKIMInput {
            signed_headers: vec![],
            signature: vec![0x33; 255],
            public_key_der: vec![],
            from_domain: vec![],
            rsa_challenge_seed: [0u8; 32],
        };
        assert!(input.as_ref().is_err());
    }

    #[test]
    fn dkim_input_ref_rejects_truncated_payload() {
        let input = DKIMInputRef {
            signed_headers: b"abc",
            signature: Bytes2048([0x11; 256]),
            public_key_der: b"def",
            from_domain: b"ghi",
            rsa_challenge_seed: [9u8; 32],
        };
        let mut encoded = postcard::to_allocvec(&input).unwrap();
        encoded.pop();
        assert!(postcard::from_bytes::<DKIMInputRef<'_>>(&encoded).is_err());
    }

    #[test]
    fn dkim_input_ref_rejects_length_overflow() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 256]);
        let encoded = postcard::to_allocvec(payload.as_slice()).unwrap();
        assert!(postcard::from_bytes::<DKIMInputRef<'_>>(&encoded).is_err());
    }

    #[test]
    fn dkim_input_ref_rejects_trailing_bytes() {
        let input = DKIMInputRef {
            signed_headers: b"abc",
            signature: Bytes2048([0x22; 256]),
            public_key_der: b"def",
            from_domain: b"ghi",
            rsa_challenge_seed: [4u8; 32],
        };
        let mut payload = input.pack_payload();
        payload.push(0xaa);
        let encoded = postcard::to_allocvec(payload.as_slice()).unwrap();
        assert!(postcard::from_bytes::<DKIMInputRef<'_>>(&encoded).is_err());
    }
}
