use std::fs::File;
use std::io::Read;
use der::Encode;
use der::asn1::{ObjectIdentifier, Null, OctetStringRef};
use sha2::{Digest, Sha256};
use sha1::Sha1;

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

#[derive(Clone, Debug, der::Sequence)]
pub struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Null,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct MessageImprint<'a> {
    pub hash_algorithm: AlgorithmIdentifier,
    pub hashed_message: OctetStringRef<'a>,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct TimeStampReq<'a> {
    pub version: u8,
    pub message_imprint: MessageImprint<'a>,
    pub nonce: u64,
}

/// Computes the hash of a file using the specified algorithm (sha1 or sha256).
pub fn compute_file_digest(path: &str, alg: &str) -> Result<Vec<u8>, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Dosya açılamadı: {:?}", e))?;
    
    let mut buffer = vec![0u8; 8192];
    
    match alg.to_lowercase().as_str() {
        "sha1" => {
            let mut hasher = Sha1::new();
            loop {
                let count = file.read(&mut buffer)
                    .map_err(|e| format!("Dosya okuma hatası: {:?}", e))?;
                if count == 0 { break; }
                hasher.update(&buffer[..count]);
            }
            Ok(hasher.finalize().to_vec())
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let count = file.read(&mut buffer)
                    .map_err(|e| format!("Dosya okuma hatası: {:?}", e))?;
                if count == 0 { break; }
                hasher.update(&buffer[..count]);
            }
            Ok(hasher.finalize().to_vec())
        }
        _ => Err(format!("Desteklenmeyen hash algoritması: {}", alg)),
    }
}

/// Creates an RFC 3161 TimeStampReq DER-encoded structure.
pub fn build_tsa_request(digest: &[u8], hash_alg: &str) -> Result<Vec<u8>, String> {
    let oid = match hash_alg.to_lowercase().as_str() {
        "sha1" => OID_SHA1,
        "sha256" => OID_SHA256,
        _ => return Err(format!("Desteklenmeyen hash algoritması: {}", hash_alg)),
    };

    let nonce = (chrono::Utc::now().timestamp_millis() & i64::MAX) as u64;

    let req = TimeStampReq {
        version: 1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: Null,
            },
            hashed_message: OctetStringRef::new(digest)
                .map_err(|e| format!("ASN.1 digest hatası: {:?}", e))?,
        },
        nonce,
    };

    let der_bytes = req.to_der()
        .map_err(|e| format!("TSA isteği oluşturulamadı (DER hatası): {:?}", e))?;

    Ok(der_bytes)
}
