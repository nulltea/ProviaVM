#![no_std]
extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
pub use jolt_inlines_rsa::{Bytes2048, Step2048, Witness2048};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Core I/O types
// ---------------------------------------------------------------------------

/// Host pre-parses SOD/CMS and extracts these fields for the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassportInput {
    /// Raw EF.DG1 bytes (TLV-wrapped MRZ). Guest hashes this.
    pub dg1: Vec<u8>,
    /// CMS encapContentInfo value — the LDS Security Object (DER).
    /// Contains the DG hash table. Guest hashes this to check messageDigest binding.
    pub encap_content: Vec<u8>,
    /// CMS signedAttrs, DER-encoded (re-tagged as SET OF per CMS spec).
    /// Guest hashes this for signature verification.
    pub signed_attrs_der: Vec<u8>,
    /// CMS signature bytes (RSA PKCS#1 v1.5).
    pub signature: Vec<u8>,
    /// Document Signer RSA public key, PKCS#1 DER.
    pub ds_pubkey_der: Vec<u8>,
    /// Transcript-bound seed for RSA witness compression checks.
    pub rsa_challenge_seed: [u8; 32],
    /// Today's date as YYYYMMDD integer (e.g. 20260315).
    pub today_yyyymmdd: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct PassportInputRef<'a> {
    pub dg1: &'a [u8],
    pub encap_content: &'a [u8],
    pub signed_attrs_der: &'a [u8],
    pub signature: Bytes2048,
    pub ds_pubkey_der: &'a [u8],
    pub rsa_challenge_seed: [u8; 32],
    pub today_yyyymmdd: u32,
}

const PASSPORT_INPUT_REF_HEADER_LEN: usize = 5 * 4 + 32 + 256;

impl<'a> PassportInputRef<'a> {
    fn pack_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(
            PASSPORT_INPUT_REF_HEADER_LEN
                + self.dg1.len()
                + self.encap_content.len()
                + self.signed_attrs_der.len()
                + self.ds_pubkey_der.len(),
        );
        payload.extend_from_slice(&(self.dg1.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(self.encap_content.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(self.signed_attrs_der.len() as u32).to_le_bytes());
        payload.extend_from_slice(&(self.ds_pubkey_der.len() as u32).to_le_bytes());
        payload.extend_from_slice(&self.today_yyyymmdd.to_le_bytes());
        payload.extend_from_slice(&self.rsa_challenge_seed);
        payload.extend_from_slice(&self.signature.0);
        payload.extend_from_slice(self.dg1);
        payload.extend_from_slice(self.encap_content);
        payload.extend_from_slice(self.signed_attrs_der);
        payload.extend_from_slice(self.ds_pubkey_der);
        payload
    }

    fn parse_packed(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < PASSPORT_INPUT_REF_HEADER_LEN {
            return Err("packed passport input too short");
        }

        let dg1_len = read_len(bytes, 0)?;
        let encap_content_len = read_len(bytes, 4)?;
        let signed_attrs_der_len = read_len(bytes, 8)?;
        let ds_pubkey_der_len = read_len(bytes, 12)?;
        let today_yyyymmdd = read_len(bytes, 16)? as u32;

        let mut rsa_challenge_seed = [0u8; 32];
        rsa_challenge_seed.copy_from_slice(&bytes[20..52]);

        let mut signature = [0u8; 256];
        signature.copy_from_slice(&bytes[52..308]);

        let mut cursor = PASSPORT_INPUT_REF_HEADER_LEN;
        let dg1 = take_packed_slice(bytes, &mut cursor, dg1_len)?;
        let encap_content = take_packed_slice(bytes, &mut cursor, encap_content_len)?;
        let signed_attrs_der = take_packed_slice(bytes, &mut cursor, signed_attrs_der_len)?;
        let ds_pubkey_der = take_packed_slice(bytes, &mut cursor, ds_pubkey_der_len)?;

        if cursor != bytes.len() {
            return Err("packed passport input has trailing bytes");
        }

        Ok(Self {
            dg1,
            encap_content,
            signed_attrs_der,
            signature: Bytes2048(signature),
            ds_pubkey_der,
            rsa_challenge_seed,
            today_yyyymmdd,
        })
    }
}

impl Serialize for PassportInputRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.pack_payload())
    }
}

impl<'de> Deserialize<'de> for PassportInputRef<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PassportInputRefVisitor;

        impl<'de> Visitor<'de> for PassportInputRefVisitor {
            type Value = PassportInputRef<'de>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("packed passport input bytes")
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                PassportInputRef::parse_packed(value).map_err(E::custom)
            }

            fn visit_bytes<E>(self, _value: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let leaked: &'de [u8] = Box::leak(_value.to_vec().into_boxed_slice());
                PassportInputRef::parse_packed(leaked).map_err(E::custom)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let leaked: &'de [u8] = Box::leak(value.into_boxed_slice());
                PassportInputRef::parse_packed(leaked).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(PassportInputRefVisitor)
    }
}

impl PassportInput {
    pub fn as_ref(&self) -> Result<PassportInputRef<'_>, &'static str> {
        let signature: [u8; 256] = self.signature.as_slice().try_into().map_err(|_| "signature must be 256 bytes")?;
        Ok(PassportInputRef {
            dg1: &self.dg1,
            encap_content: &self.encap_content,
            signed_attrs_der: &self.signed_attrs_der,
            signature: Bytes2048(signature),
            ds_pubkey_der: &self.ds_pubkey_der,
            rsa_challenge_seed: self.rsa_challenge_seed,
            today_yyyymmdd: self.today_yyyymmdd,
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

/// Public output committed by the guest proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportOutput {
    /// All passive auth checks passed.
    pub passive_auth_valid: bool,
    /// Holder is 18 or older.
    pub over_18: bool,
    /// 3-letter issuing state code from MRZ.
    pub issuing_country: [u8; 3],
}

// ---------------------------------------------------------------------------
// MRZ parsing (TD3 format, 2 lines × 44 chars = 88 bytes)
// ---------------------------------------------------------------------------

/// Parsed fields from a TD3 Machine Readable Zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedMrz {
    /// 3-letter issuing state code (e.g. b"UTO").
    pub issuing_country: [u8; 3],
    /// Date of birth as 6 ASCII digits YYMMDD.
    pub dob_yymmdd: [u8; 6],
}

/// Strip the DG1 TLV wrapper and return the raw 88-byte TD3 MRZ.
///
/// EF.DG1 structure: tag 0x61, length, then tag 0x5F1F, length, then MRZ bytes.
pub fn unwrap_dg1_to_mrz(dg1: &[u8]) -> Option<&[u8]> {
    let (_, inner) = read_tlv(dg1)?;
    if inner.first() != Some(&0x5F) || inner.get(1) != Some(&0x1F) {
        return None;
    }
    // Tag 0x5F1F is a two-byte tag
    let (_, mrz) = read_tlv_two_byte_tag(&inner[2..])?;
    if mrz.len() == 88 {
        Some(mrz)
    } else {
        None
    }
}

/// Parse a TD3 MRZ (88 bytes) into structured fields.
///
/// Layout:
///   Line 1 (bytes 0..44):  [0] type, [1] subtype, [2..5] issuing country, [5..44] name
///   Line 2 (bytes 44..88): [0..9] doc number, [9] check, [10..13] nationality,
///                           [13..19] DOB YYMMDD, [19] check, [20] sex,
///                           [21..27] expiry YYMMDD, ...
pub fn parse_td3_mrz(mrz: &[u8]) -> Option<ParsedMrz> {
    if mrz.len() != 88 {
        return None;
    }
    let issuing_country: [u8; 3] = [mrz[2], mrz[3], mrz[4]];
    let line2 = &mrz[44..];
    let dob_yymmdd: [u8; 6] = [line2[13], line2[14], line2[15], line2[16], line2[17], line2[18]];
    Some(ParsedMrz { issuing_country, dob_yymmdd })
}

// ---------------------------------------------------------------------------
// Age predicate
// ---------------------------------------------------------------------------

/// Expand a 2-digit MRZ year to a 4-digit year.
/// ICAO rule for DOB: YY > 50 → 19YY, else 20YY.
fn expand_mrz_year(yy: u8) -> u32 {
    if yy > 50 {
        1900 + yy as u32
    } else {
        2000 + yy as u32
    }
}

/// Parse 2 ASCII digit chars into a u8 (e.g. b"74" → 74).
fn ascii2_to_u8(hi: u8, lo: u8) -> Option<u8> {
    let h = hi.checked_sub(b'0')?;
    let l = lo.checked_sub(b'0')?;
    if h > 9 || l > 9 {
        return None;
    }
    Some(h * 10 + l)
}

/// Check whether a person with the given DOB (YYMMDD ASCII digits) is at least 18
/// on the given date (YYYYMMDD integer, e.g. 20260315).
pub fn is_over_18(dob_yymmdd: [u8; 6], today_yyyymmdd: u32) -> bool {
    let yy = match ascii2_to_u8(dob_yymmdd[0], dob_yymmdd[1]) {
        Some(v) => v,
        None => return false,
    };
    let mm = match ascii2_to_u8(dob_yymmdd[2], dob_yymmdd[3]) {
        Some(v) => v,
        None => return false,
    };
    let dd = match ascii2_to_u8(dob_yymmdd[4], dob_yymmdd[5]) {
        Some(v) => v,
        None => return false,
    };

    let birth_year = expand_mrz_year(yy);
    let birth_mmdd = (mm as u32) * 100 + dd as u32;

    let today_year = today_yyyymmdd / 10000;
    let today_mmdd = today_yyyymmdd % 10000;

    let mut age = today_year.wrapping_sub(birth_year);
    if today_mmdd < birth_mmdd {
        age = age.wrapping_sub(1);
    }
    age >= 18
}

// ---------------------------------------------------------------------------
// Byte-containment helper
// ---------------------------------------------------------------------------

/// Check whether `haystack` contains `needle` as a contiguous subsequence.
pub fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Minimal TLV helpers (not a general ASN.1 parser)
// ---------------------------------------------------------------------------

/// Read a single-byte-tag TLV. Returns (tag, value_slice).
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    let (len, offset) = read_der_length(&data[1..])?;
    let value = data.get(1 + offset..1 + offset + len)?;
    Some((tag, value))
}

/// Read value after a two-byte tag has already been consumed.
/// `data` starts right after the two-byte tag.
fn read_tlv_two_byte_tag(data: &[u8]) -> Option<((), &[u8])> {
    let (len, offset) = read_der_length(data)?;
    let value = data.get(offset..offset + len)?;
    Some(((), value))
}

/// Decode a DER length field. Returns (length_value, bytes_consumed).
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x81 {
        let len = *data.get(1)? as usize;
        Some((len, 2))
    } else if first == 0x82 {
        let hi = *data.get(1)? as usize;
        let lo = *data.get(2)? as usize;
        Some((hi << 8 | lo, 3))
    } else {
        // Lengths > 65535 not expected for passport data
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn test_parse_td3_mrz() {
        // ICAO example: P<UTOERIKSSON<<ANNA<MARIA...
        let line1 = b"P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<";
        let line2 = b"L898902C36UTO7408122F1204159ZE184226B<<<<<<0";
        assert_eq!(line1.len(), 44);
        assert_eq!(line2.len(), 44);

        let mut mrz = [0u8; 88];
        mrz[..44].copy_from_slice(line1);
        mrz[44..].copy_from_slice(line2);

        let parsed = parse_td3_mrz(&mrz).unwrap();
        assert_eq!(&parsed.issuing_country, b"UTO");
        assert_eq!(&parsed.dob_yymmdd, b"740812");
    }

    #[test]
    fn test_is_over_18_yes() {
        // Born 2000-03-15, today 2026-03-15 → age 26
        assert!(is_over_18(*b"000315", 20260315));
    }

    #[test]
    fn test_is_over_18_exactly_18() {
        // Born 2008-03-15, today 2026-03-15 → exactly 18
        assert!(is_over_18(*b"080315", 20260315));
    }

    #[test]
    fn test_is_over_18_one_day_before() {
        // Born 2008-03-16, today 2026-03-15 → still 17
        assert!(!is_over_18(*b"080316", 20260315));
    }

    #[test]
    fn test_is_over_18_1900s() {
        // Born 1974-08-12 (YY=74 > 50 → 1974), today 2026-03-15 → age 51
        assert!(is_over_18(*b"740812", 20260315));
    }

    #[test]
    fn test_is_over_18_minor() {
        // Born 2015-01-01, today 2026-03-15 → age 11
        assert!(!is_over_18(*b"150101", 20260315));
    }

    #[test]
    fn test_unwrap_dg1_to_mrz() {
        // Build a minimal DG1: 0x61 || len || 0x5F1F || len || 88 MRZ bytes
        let mrz = [b'X'; 88];
        let mut dg1 = Vec::new();
        dg1.push(0x61);
        // inner length = 2 (tag 5F1F) + 1 (length byte) + 88 = 91
        dg1.push(91);
        dg1.push(0x5F);
        dg1.push(0x1F);
        dg1.push(88);
        dg1.extend_from_slice(&mrz);

        let result = unwrap_dg1_to_mrz(&dg1).unwrap();
        assert_eq!(result.len(), 88);
        assert_eq!(result, &mrz[..]);
    }

    #[test]
    fn test_contains_subsequence() {
        let haystack = b"hello world";
        assert!(contains_subsequence(haystack, b"world"));
        assert!(contains_subsequence(haystack, b"hello"));
        assert!(contains_subsequence(haystack, b"lo wo"));
        assert!(!contains_subsequence(haystack, b"worlds"));
        assert!(contains_subsequence(haystack, b""));
        assert!(!contains_subsequence(b"", b"a"));
    }

    #[test]
    fn test_ascii2_to_u8() {
        assert_eq!(ascii2_to_u8(b'0', b'0'), Some(0));
        assert_eq!(ascii2_to_u8(b'7', b'4'), Some(74));
        assert_eq!(ascii2_to_u8(b'9', b'9'), Some(99));
        assert_eq!(ascii2_to_u8(b'a', b'0'), None);
    }

    #[test]
    fn passport_input_as_ref_normalizes_signature() {
        let input = PassportInput {
            dg1: b"dg1".to_vec(),
            encap_content: b"encap".to_vec(),
            signed_attrs_der: b"attrs".to_vec(),
            signature: vec![0x44; 256],
            ds_pubkey_der: b"\x30\x82\x01".to_vec(),
            rsa_challenge_seed: [5u8; 32],
            today_yyyymmdd: 20260317,
        };

        let input_ref = input.as_ref().unwrap();
        assert_eq!(input_ref.dg1, input.dg1.as_slice());
        assert_eq!(input_ref.encap_content, input.encap_content.as_slice());
        assert_eq!(input_ref.signed_attrs_der, input.signed_attrs_der.as_slice());
        assert_eq!(input_ref.signature.0, [0x44; 256]);
        assert_eq!(input_ref.ds_pubkey_der, input.ds_pubkey_der.as_slice());
        assert_eq!(input_ref.rsa_challenge_seed, input.rsa_challenge_seed);
        assert_eq!(input_ref.today_yyyymmdd, input.today_yyyymmdd);
    }

    #[test]
    fn passport_input_ref_postcard_roundtrip() {
        let input = PassportInputRef {
            dg1: b"dg1",
            encap_content: b"encap",
            signed_attrs_der: b"attrs",
            signature: Bytes2048([0x22; 256]),
            ds_pubkey_der: b"\x30\x82\x01",
            rsa_challenge_seed: [3u8; 32],
            today_yyyymmdd: 20260317,
        };

        let encoded = postcard::to_allocvec(&input).unwrap();
        let decoded: PassportInputRef<'_> = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.dg1, input.dg1);
        assert_eq!(decoded.encap_content, input.encap_content);
        assert_eq!(decoded.signed_attrs_der, input.signed_attrs_der);
        assert_eq!(decoded.signature, input.signature);
        assert_eq!(decoded.ds_pubkey_der, input.ds_pubkey_der);
        assert_eq!(decoded.rsa_challenge_seed, input.rsa_challenge_seed);
        assert_eq!(decoded.today_yyyymmdd, input.today_yyyymmdd);
    }

    #[test]
    fn passport_input_as_ref_rejects_short_signature() {
        let input = PassportInput {
            dg1: Vec::new(),
            encap_content: Vec::new(),
            signed_attrs_der: Vec::new(),
            signature: vec![0x11; 255],
            ds_pubkey_der: Vec::new(),
            rsa_challenge_seed: [0u8; 32],
            today_yyyymmdd: 20260317,
        };
        assert!(input.as_ref().is_err());
    }

    #[test]
    fn passport_input_ref_rejects_truncated_payload() {
        let input = PassportInputRef {
            dg1: b"dg1",
            encap_content: b"encap",
            signed_attrs_der: b"attrs",
            signature: Bytes2048([0x22; 256]),
            ds_pubkey_der: b"\x30\x82\x01",
            rsa_challenge_seed: [3u8; 32],
            today_yyyymmdd: 20260317,
        };
        let mut encoded = postcard::to_allocvec(&input).unwrap();
        encoded.pop();
        assert!(postcard::from_bytes::<PassportInputRef<'_>>(&encoded).is_err());
    }

    #[test]
    fn passport_input_ref_rejects_length_overflow() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&20260317u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&[0u8; 256]);
        let encoded = postcard::to_allocvec(payload.as_slice()).unwrap();
        assert!(postcard::from_bytes::<PassportInputRef<'_>>(&encoded).is_err());
    }

    #[test]
    fn passport_input_ref_rejects_trailing_bytes() {
        let input = PassportInputRef {
            dg1: b"dg1",
            encap_content: b"encap",
            signed_attrs_der: b"attrs",
            signature: Bytes2048([0x44; 256]),
            ds_pubkey_der: b"\x30\x82\x01",
            rsa_challenge_seed: [4u8; 32],
            today_yyyymmdd: 20260317,
        };
        let mut payload = input.pack_payload();
        payload.push(0xaa);
        let encoded = postcard::to_allocvec(payload.as_slice()).unwrap();
        assert!(postcard::from_bytes::<PassportInputRef<'_>>(&encoded).is_err());
    }
}
