use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hex::encode as hex_encode;
use ink_core::{InkError, InkResult};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ARGON_ITERATIONS: u32 = 5;
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PARALLELISM: u32 = 1;
const ARGON_OUTPUT_BYTES: usize = 64;

const PROTOCOL_VERSION_004: &str = "004";
const EMPTY_JSON_BASE64: &str = "e30=";
const KEY_BYTES_256: usize = 32;
const NONCE_BYTES_192: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedRootCredentials {
    pub master_key: String,
    pub server_password: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protocol004Components {
    pub version: String,
    pub nonce: String,
    pub ciphertext: String,
    pub authenticated_data: String,
    pub additional_data: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecryptedProtocolString {
    pub plaintext: String,
    pub authenticated_data: Value,
    pub additional_data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItemPayload004 {
    pub content: String,
    pub enc_item_key: String,
    pub generated_item_key: String,
}

pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

pub fn derive_root_credentials_004(
    password: &str,
    identifier: &str,
    pw_nonce: &str,
) -> InkResult<DerivedRootCredentials> {
    if password.is_empty() {
        return Err(InkError::auth("password is required"));
    }

    let normalized_identifier = normalize_email(identifier);
    if normalized_identifier.is_empty() {
        return Err(InkError::auth(
            "identifier is required for root key derivation",
        ));
    }

    let nonce = pw_nonce.trim();
    if nonce.is_empty() {
        return Err(InkError::auth(
            "pw_nonce is required for root key derivation",
        ));
    }

    let salt = generate_salt_004(&normalized_identifier, nonce);
    let params = Params::new(
        ARGON_MEMORY_KIB,
        ARGON_ITERATIONS,
        ARGON_PARALLELISM,
        Some(ARGON_OUTPUT_BYTES),
    )
    .map_err(|err| InkError::crypto(format!("invalid argon2 parameters: {err}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; ARGON_OUTPUT_BYTES];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|err| InkError::crypto(format!("failed to derive root credentials: {err}")))?;

    let master_key = hex_encode(&output[..32]);
    let server_password = hex_encode(&output[32..]);

    Ok(DerivedRootCredentials {
        master_key,
        server_password,
    })
}

pub fn generate_items_key_004() -> String {
    let mut bytes = [0u8; KEY_BYTES_256];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_encode(bytes)
}

pub fn make_item_authenticated_data_004(
    uuid: &str,
    key_params: Option<&Value>,
    key_system_identifier: Option<&str>,
    shared_vault_uuid: Option<&str>,
) -> InkResult<Value> {
    let uuid = uuid.trim();
    if uuid.is_empty() {
        return Err(InkError::crypto("uuid is required for authenticated data"));
    }

    let mut map = Map::new();
    map.insert("u".to_string(), Value::String(uuid.to_string()));
    map.insert(
        "v".to_string(),
        Value::String(PROTOCOL_VERSION_004.to_string()),
    );

    if let Some(kp) = key_params {
        map.insert("kp".to_string(), canonicalize_json(kp));
    }

    if let Some(ksi) = key_system_identifier
        && !ksi.trim().is_empty()
    {
        map.insert("ksi".to_string(), Value::String(ksi.trim().to_string()));
    }

    if let Some(svu) = shared_vault_uuid
        && !svu.trim().is_empty()
    {
        map.insert("svu".to_string(), Value::String(svu.trim().to_string()));
    }

    Ok(canonicalize_json(&Value::Object(map)))
}

pub fn encode_consistent_base64_json(value: &Value) -> InkResult<String> {
    let canonical = canonicalize_json(value);
    let json = serde_json::to_string(&canonical)
        .map_err(|err| InkError::crypto(format!("failed to encode json: {err}")))?;
    Ok(BASE64.encode(json.as_bytes()))
}

pub fn parse_protocol_string_004(input: &str) -> InkResult<Protocol004Components> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err(InkError::crypto("encrypted protocol string is empty"));
    }

    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() < 4 {
        return Err(InkError::crypto(format!(
            "invalid 004 string: expected at least 4 components, got {}",
            parts.len()
        )));
    }

    if parts[0] != PROTOCOL_VERSION_004 {
        return Err(InkError::crypto(format!(
            "unsupported protocol version '{}'",
            parts[0]
        )));
    }

    Ok(Protocol004Components {
        version: parts[0].to_string(),
        nonce: parts[1].to_string(),
        ciphertext: parts[2].to_string(),
        authenticated_data: parts[3].to_string(),
        additional_data: parts.get(4).map(|value| (*value).to_string()),
    })
}

pub fn decrypt_protocol_string_004(
    input: &str,
    key_hex: &str,
) -> InkResult<DecryptedProtocolString> {
    let components = parse_protocol_string_004(input)?;
    let key = decode_key_hex(key_hex)?;
    let nonce = decode_nonce_hex(&components.nonce)?;
    let ciphertext = BASE64
        .decode(components.ciphertext.as_bytes())
        .map_err(|err| InkError::crypto(format!("invalid ciphertext base64: {err}")))?;

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| InkError::crypto(format!("invalid 256-bit key: {err}")))?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: components.authenticated_data.as_bytes(),
            },
        )
        .map_err(|_| InkError::crypto("failed to decrypt 004 payload"))?;

    let plaintext = String::from_utf8(plaintext)
        .map_err(|err| InkError::crypto(format!("decrypted payload is not utf8: {err}")))?;

    let authenticated_data = decode_base64_json(&components.authenticated_data)?;
    let additional_data = match components.additional_data {
        Some(value) => Some(decode_base64_json(&value)?),
        None => None,
    };

    Ok(DecryptedProtocolString {
        plaintext,
        authenticated_data,
        additional_data,
    })
}

pub fn encrypt_protocol_string_004(
    plaintext: &str,
    key_hex: &str,
    authenticated_data: &Value,
    additional_data: Option<&Value>,
) -> InkResult<String> {
    let key = decode_key_hex(key_hex)?;
    let authenticated_data = encode_consistent_base64_json(authenticated_data)?;
    let additional_data = additional_data
        .map(encode_consistent_base64_json)
        .transpose()?
        .unwrap_or_else(|| EMPTY_JSON_BASE64.to_string());

    let mut nonce = [0u8; NONCE_BYTES_192];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| InkError::crypto(format!("invalid 256-bit key: {err}")))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: authenticated_data.as_bytes(),
            },
        )
        .map_err(|_| InkError::crypto("failed to encrypt 004 payload"))?;

    let nonce_hex = hex_encode(nonce);
    let ciphertext_base64 = BASE64.encode(ciphertext);

    Ok(format!(
        "{PROTOCOL_VERSION_004}:{nonce_hex}:{ciphertext_base64}:{authenticated_data}:{additional_data}"
    ))
}

pub fn decrypt_item_key_004(enc_item_key: &str, wrapping_key_hex: &str) -> InkResult<String> {
    let decrypted = decrypt_protocol_string_004(enc_item_key, wrapping_key_hex)?;
    let item_key = decrypted.plaintext.trim();
    validate_hex_key(item_key)?;
    Ok(item_key.to_string())
}

pub fn decrypt_item_content_004(content: &str, item_key_hex: &str) -> InkResult<Value> {
    let decrypted = decrypt_protocol_string_004(content, item_key_hex)?;
    serde_json::from_str(&decrypted.plaintext)
        .map_err(|err| InkError::crypto(format!("failed to parse decrypted item json: {err}")))
}

pub fn decrypt_item_payload_004(
    content: &str,
    enc_item_key: &str,
    wrapping_key_hex: &str,
) -> InkResult<Value> {
    let item_key = decrypt_item_key_004(enc_item_key, wrapping_key_hex)?;
    decrypt_item_content_004(content, &item_key)
}

pub fn encrypt_item_payload_004(
    content: &Value,
    wrapping_key_hex: &str,
    uuid: &str,
    key_params: Option<&Value>,
    key_system_identifier: Option<&str>,
    shared_vault_uuid: Option<&str>,
) -> InkResult<EncryptedItemPayload004> {
    let item_key = generate_items_key_004();
    let authenticated_data = make_item_authenticated_data_004(
        uuid,
        key_params,
        key_system_identifier,
        shared_vault_uuid,
    )?;

    let canonical_content = canonicalize_json(content);
    let content_plaintext = serde_json::to_string(&canonical_content)
        .map_err(|err| InkError::crypto(format!("failed to encode item content json: {err}")))?;

    let content_encrypted = encrypt_protocol_string_004(
        &content_plaintext,
        &item_key,
        &authenticated_data,
        Some(&Value::Object(Map::new())),
    )?;
    let key_encrypted = encrypt_protocol_string_004(
        &item_key,
        wrapping_key_hex,
        &authenticated_data,
        Some(&Value::Object(Map::new())),
    )?;

    Ok(EncryptedItemPayload004 {
        content: content_encrypted,
        enc_item_key: key_encrypted,
        generated_item_key: item_key,
    })
}

fn decode_base64_json(input: &str) -> InkResult<Value> {
    let raw = BASE64
        .decode(input.as_bytes())
        .map_err(|err| InkError::crypto(format!("invalid base64 json: {err}")))?;

    serde_json::from_slice(&raw)
        .map_err(|err| InkError::crypto(format!("invalid base64 json payload: {err}")))
}

fn decode_key_hex(key_hex: &str) -> InkResult<[u8; KEY_BYTES_256]> {
    validate_hex_key(key_hex)?;
    let decoded = hex::decode(key_hex)
        .map_err(|err| InkError::crypto(format!("invalid key hex string: {err}")))?;

    let mut bytes = [0u8; KEY_BYTES_256];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn decode_nonce_hex(nonce_hex: &str) -> InkResult<[u8; NONCE_BYTES_192]> {
    let decoded = hex::decode(nonce_hex)
        .map_err(|err| InkError::crypto(format!("invalid nonce hex string: {err}")))?;

    if decoded.len() != NONCE_BYTES_192 {
        return Err(InkError::crypto(format!(
            "invalid nonce length {}; expected {} bytes",
            decoded.len(),
            NONCE_BYTES_192
        )));
    }

    let mut bytes = [0u8; NONCE_BYTES_192];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn validate_hex_key(input: &str) -> InkResult<()> {
    if input.len() != KEY_BYTES_256 * 2 {
        return Err(InkError::crypto(format!(
            "invalid key length {}; expected {} hex chars",
            input.len(),
            KEY_BYTES_256 * 2
        )));
    }

    if !input.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(InkError::crypto("key must be a hex string"));
    }

    Ok(())
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();

            let mut output = Map::new();
            for key in keys {
                if let Some(item) = map.get(key) {
                    output.insert(key.to_string(), canonicalize_json(item));
                }
            }

            Value::Object(output)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

fn generate_salt_004(identifier: &str, nonce: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(identifier.as_bytes());
    hasher.update(b":");
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();

    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const FIXTURE_ITEMS_KEY_CONTENT: &str = "004:77a986823b8ffdd87164b6f541de6ed420b70ac67e055774:+8cjww1QbyXNX+PSKeCwmnysv0rAoEaKh409VWQJpDbEy/pPZCT6c0rKxLzvyMiSq6EwkOiduZMzokRgCKP7RuRqNPJceWsxNnpIUwa40KR1IP2tdreW4J8v9pFEzPMec1oq40u+c+UI/Y6ChOLV/4ozyWmpQCK3y8Ugm7B1/FzaeDs9Ie6Mvf98+XECoi0fWv9SO2TeBvq1G24LXd4zf0j8jd0sKZbLPXH0+gaUXtBH7A56lHvB0ED9NuiHI8xopTBd9ogKlz/b5+JB4zA2zQCQ3WMEE1qz6WeB2S4FMomgeO1e3trabdU0ICu0WMvDVii4qNlQo/inD41oHXKeV5QwnYoGjPrLJIaP0hiLKhDURTHygCdvWdp63OWI+aGxv0/HI+nfcRsqSE+aYECrWB/kp/c5yTrEqBEafuWZkw==:eyJrcCI6eyJpZGVudGlmaWVyIjoicGxheWdyb3VuZEBiaXRhci5pbyIsInB3X25vbmNlIjoiNjUxYWUxZWM5NTgwMzM5YTM1NjdlZTdmMGY4NjcyNDkyZGUyYzE2NmE1NTZjMTNkMTE5NzI4YTAzYzYwZjc5MyIsInZlcnNpb24iOiIwMDQiLCJvcmlnaW5hdGlvbiI6InByb3RvY29sLXVwZ3JhZGUiLCJjcmVhdGVkIjoiMTYxNDc4NDE5MjQ5NyJ9LCJ1IjoiMTAwNTFiZTctNGNhMi00YWYzLWFhZTktMDIxOTM5ZGY0ZmFiIiwidiI6IjAwNCJ9";
    const FIXTURE_ITEMS_KEY_ENC_KEY: &str = "004:d25deb224251b4705a44d8ce125a62f6a2f0e0e856603e8f:FEv1pfU/VfY7XhJrTfpcdhaSBfmNySTQtHohFYDm8V84KlyF5YaXRKV7BfXsa77DKTjOCU/EHHsWwhBEEfsNnzNySHxTHNc26bpoz0V8h50=:eyJrcCI6eyJpZGVudGlmaWVyIjoicGxheWdyb3VuZEBiaXRhci5pbyIsInB3X25vbmNlIjoiNjUxYWUxZWM5NTgwMzM5YTM1NjdlZTdmMGY4NjcyNDkyZGUyYzE2NmE1NTZjMTNkMTE5NzI4YTAzYzYwZjc5MyIsInZlcnNpb24iOiIwMDQiLCJvcmlnaW5hdGlvbiI6InByb3RvY29sLXVwZ3JhZGUiLCJjcmVhdGVkIjoiMTYxNDc4NDE5MjQ5NyJ9LCJ1IjoiMTAwNTFiZTctNGNhMi00YWYzLWFhZTktMDIxOTM5ZGY0ZmFiIiwidiI6IjAwNCJ9";

    #[test]
    fn normalize_email_trims_and_lowercases() {
        assert_eq!(normalize_email("  USER@Example.COM "), "user@example.com");
    }

    #[test]
    fn derivation_matches_reference_vector() {
        let derived = derive_root_credentials_004(
            "debugtest",
            "sn004@lessknown.co.uk",
            "2c409996650e46c748856fbd6aa549f89f35be055a8f9bfacdf0c4b29b2152e9",
        )
        .expect("derive root credentials");

        assert_eq!(
            derived.master_key,
            "2396d6ac0bc70fe45db1d2bcf3daa522603e9c6fcc88dc933ce1a3a31bbc08ed"
        );
        assert_eq!(
            derived.server_password,
            "a5eb9fbc767eafd6e54fd9d3646b19520e038ba2ccc9cceddf2340b37b788b47"
        );
    }

    #[test]
    fn consistent_base64_json_sorts_keys() {
        let encoded = encode_consistent_base64_json(&json!({
            "v": "004",
            "u": "abc",
            "nested": {"z": 1, "a": 2}
        }))
        .expect("base64 json");

        let decoded =
            String::from_utf8(BASE64.decode(encoded).expect("decode base64")).expect("utf8");
        assert_eq!(decoded, r#"{"nested":{"a":2,"z":1},"u":"abc","v":"004"}"#);
    }

    #[test]
    fn protocol_string_round_trip_succeeds() {
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let authenticated_data = json!({"u": "123", "v": "004"});

        let encrypted =
            encrypt_protocol_string_004("hello", key, &authenticated_data, None).expect("encrypt");
        let decrypted = decrypt_protocol_string_004(&encrypted, key).expect("decrypt");

        assert_eq!(decrypted.plaintext, "hello");
        assert_eq!(decrypted.authenticated_data["u"], "123");
        assert_eq!(decrypted.authenticated_data["v"], "004");
    }

    #[test]
    fn decrypts_official_items_key_fixture() {
        let derived = derive_root_credentials_004(
            "password",
            "playground@bitar.io",
            "651ae1ec9580339a3567ee7f0f8672492de2c166a556c13d119728a03c60f793",
        )
        .expect("derive root key");

        let content = decrypt_item_payload_004(
            FIXTURE_ITEMS_KEY_CONTENT,
            FIXTURE_ITEMS_KEY_ENC_KEY,
            &derived.master_key,
        )
        .expect("decrypt fixture items key");

        assert_eq!(content["version"], "003");
        assert!(content["itemsKey"].is_string());
        assert_eq!(
            content["itemsKey"].as_str().expect("items key").len(),
            KEY_BYTES_256 * 2
        );
    }

    #[test]
    fn item_payload_encrypt_decrypt_round_trip_succeeds() {
        let wrapping_key = "8899aabbccddeeff00112233445566778899aabbccddeeff0011223344556677";
        let content = json!({"title": "Test", "text": "Body"});

        let encrypted =
            encrypt_item_payload_004(&content, wrapping_key, "item-uuid", None, None, None)
                .expect("encrypt payload");
        let decrypted =
            decrypt_item_payload_004(&encrypted.content, &encrypted.enc_item_key, wrapping_key)
                .expect("decrypt payload");

        assert_eq!(decrypted["title"], "Test");
        assert_eq!(decrypted["text"], "Body");
    }
}
