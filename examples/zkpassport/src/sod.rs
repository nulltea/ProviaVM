/// CMS/SOD parsing for real passport fixture files.
///
/// Parses a real EF.SOD (CMS SignedData) and extracts the fields
/// needed to construct a PassportInput for guest verification.
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::OctetStringRef;
use der::{Decode, SliceReader, Tag, Tagged};
use zkpassport_core::PassportInput;

/// Fields extracted from a real SOD file.
pub struct ParsedSod {
    /// The LDS Security Object bytes (encapContentInfo.eContent).
    pub encap_content: Vec<u8>,
    /// DER-encoded signedAttrs, re-tagged as SET OF (0x31) for signature hashing.
    pub signed_attrs_der: Vec<u8>,
    /// SignerInfo.signature bytes.
    pub signature: Vec<u8>,
}

/// Parse raw EF.SOD bytes into the fields needed for guest verification.
///
/// EF.SOD starts with a TLV wrapper (tag 0x77) around the CMS ContentInfo.
/// Some passports omit this wrapper.
pub fn parse_sod(sod_bytes: &[u8]) -> eyre::Result<ParsedSod> {
    // Strip optional 0x77 wrapper
    let cms_bytes = strip_sod_wrapper(sod_bytes);

    let content_info = ContentInfo::from_der(cms_bytes)
        .map_err(|e| eyre::eyre!("parse ContentInfo: {}", e))?;

    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|e| eyre::eyre!("parse SignedData: {}", e))?;

    // Extract encapContentInfo.eContent (the LDS Security Object)
    let encap_content_info = &signed_data.encap_content_info;
    let econtent = encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| eyre::eyre!("missing eContent in encapContentInfo"))?;

    // eContent is an EXPLICIT [0] OCTET STRING — decode the inner OCTET STRING
    let econtent_bytes = econtent
        .decode_as::<OctetStringRef<'_>>()
        .map_err(|e| eyre::eyre!("decode eContent OCTET STRING: {}", e))?;
    let encap_content = econtent_bytes.as_bytes().to_vec();

    // Get the first (and usually only) SignerInfo
    let signer_info = signed_data
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| eyre::eyre!("no SignerInfo in SignedData"))?;

    // Extract signedAttrs — must re-encode with SET OF tag (0x31) for hashing
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| eyre::eyre!("no signedAttrs in SignerInfo"))?;
    let mut signed_attrs_der = Vec::new();
    // The signedAttrs are stored with IMPLICIT [0] tag; for hashing we need SET OF (0x31)
    let raw = der::Encode::to_der(signed_attrs)
        .map_err(|e| eyre::eyre!("re-encode signedAttrs: {}", e))?;
    // Replace the first byte (IMPLICIT [0] = 0xA0) with SET OF (0x31)
    signed_attrs_der.extend_from_slice(&raw);
    if !signed_attrs_der.is_empty() {
        signed_attrs_der[0] = 0x31;
    }

    // Extract signature
    let signature = signer_info.signature.as_bytes().to_vec();

    Ok(ParsedSod {
        encap_content,
        signed_attrs_der,
        signature,
    })
}

/// Strip the optional EF.SOD 0x77 TLV wrapper to get raw CMS ContentInfo bytes.
fn strip_sod_wrapper(data: &[u8]) -> &[u8] {
    if data.first() == Some(&0x77) {
        // Read past tag + length
        if let Some((_len, offset)) = read_der_length(&data[1..]) {
            return &data[1 + offset..];
        }
    }
    data
}

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
        None
    }
}
