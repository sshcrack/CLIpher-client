use std::error::Error;
use std::str;
use libaes::Cipher;

use crate::encryption::hmac::{HmacInput, get_hmac};
use crate::generators::salt::generate_salt;
use crate::packager::{PackageComponents};
use crate::{constants::*};
use super::derive::derive_from_password;

pub fn encrypt_text(text: &str, password: &str, salt: Option<&str>, iv: Option<&str>) -> Result<PackageComponents, Box<dyn Error>> {
    let salt = salt.or(Some(&generate_salt()));
    let iv = hex::decode("c39aae42241b6f5c405f6f5068ab282f")?;//generate_iv();
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
        salt: salt
    })?;

    let packaged = PackageComponents {
        method: ENCRYPTION_METHOD.to_string(),
        hmac: hmac_hex,
        iv: iv_hex,
        salt: salt.to_string(),
        rounds: DERIVATION_ROUNDS,
        encrypted: encrypted
    };

    println!("Ok");
    return Ok(packaged);
}
