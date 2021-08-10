use std::error::Error;
use std::str;
use libaes::Cipher;

use crate::encryption::hmac::{HmacInput, get_hmac};
use crate::error::decryption::{DecryptEnum, DecryptError};
use crate::generators::iv::{generate_iv};
use crate::generators::salt::generate_salt;
use crate::packager::{PackageComponents, package_components, unpackage_components};
use crate::utils::binary::constant_time_compare;
use crate::{constants::*};
use super::derive::derive_from_password;

pub fn encrypt_text(text: &str, password: &str, salt: Option<String>, iv_opt: Option<String>) -> Result<String, Box<dyn Error>> {
    if salt.is_some() {
        println!("Is some salt");
    }
    let salt = salt.unwrap_or_else(|| generate_salt());
    let iv: Vec<u8>;
    if iv_opt.is_some() {
        println!("Some iv");
        iv = hex::decode(iv_opt.unwrap())?;
    } else {
        iv = generate_iv().to_vec();
    }

    let iv_hex = hex::encode(iv.to_vec());

    let derived = derive_from_password(password, &salt, DERIVATION_ROUNDS)?;
    let hmac = derived.extracted.hmac;
    let key = derived.extracted.key;


    let cipher = Cipher::new_256(&key.raw);
    let encrypted_raw = cipher.cbc_encrypt(&iv, text.as_bytes());

    let encrypted: String = base64::encode(&encrypted_raw);
    let hmac_hex = get_hmac(HmacInput {
        key: &hmac.raw,
        encrypted: &encrypted,
        iv: &iv_hex,
        salt: &salt
    })?;

    let packaged = PackageComponents {
        method: ENCRYPTION_METHOD.to_string(),
        hmac: hmac_hex,
        iv: iv_hex,
        salt: salt.to_string(),
        rounds: DERIVATION_ROUNDS,
        encrypted: encrypted
    };

    return Ok(package_components(packaged));
}

pub fn decrypt_text(packaged: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let components = unpackage_components(packaged)?;

    let salt = components.salt;
    let iv_hex = components.iv;
    let iv = hex::decode(iv_hex.clone())?;

    let derived = derive_from_password(password, &salt, DERIVATION_ROUNDS)?;
    let hmac = derived.extracted.hmac;
    let key = derived.extracted.key;

    let encrypted_b64 = components.encrypted;
    let encrypted = base64::decode(encrypted_b64.clone())?;

    let hmac_hex = get_hmac(HmacInput {
        key: &hmac.raw,
        encrypted: &encrypted_b64,
        iv: &iv_hex,
        salt: &salt
    })?;

    let old_hmac_hex = components.hmac;
    if constant_time_compare(hmac_hex, old_hmac_hex) != true {
        return Err(Box::new(DecryptError {
            error: DecryptEnum::HmacMismatch
        }));
    }

    let cipher = Cipher::new_256(&key.raw);
    let decrypted_raw = cipher.cbc_decrypt(&iv, &encrypted);
    unsafe {
        let decrypted = String::from_utf8_unchecked(decrypted_raw);
        return Ok(decrypted);
    }
}

