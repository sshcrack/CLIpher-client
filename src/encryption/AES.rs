use std::error::Error;
use std::str;
use libaes::Cipher;
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

use crate::{constants::*, generators::iv::generate_iv};
use crate::{ error::EncryptError };
use super::derive::derive_from_password;

type HmacSha256 = Hmac<Sha256>;
pub fn encrypt_text(text: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let salt = "YJCTuo96N27C"; //generate_salt();
    let iv = generate_iv();
    let iv_hex = hex::encode(iv.to_vec());

    let derived_res = derive_from_password(password, &salt, DERIVATION_ROUNDS);
    if derived_res.is_err() {
        let err = derived_res.unwrap_err();
        return Err(Box::new(EncryptError {
            error: err
        }));
    }

    let derived = derived_res.unwrap();
    let cipher = Cipher::new_256(&derived.hex_raw_key);
    let mut hmac_tool = HmacSha256::new_from_slice(&derived.hex_raw_hmac)?;

    let encryptedRaw = cipher.cbc_encrypt(&iv, text.as_bytes());
    let encrypted = str::from_utf8(&encryptedRaw)?;


    hmac_tool.update(encrypted.as_bytes());
    hmac_tool.update(iv_hex.as_bytes());
    hmac_tool.update(salt.as_bytes());

    let hmac_hex_bytes = hmac_tool.finalize().into_bytes();
    let hmac_hex = str::from_utf8(&hmac_hex_bytes)?;

    let formatted = format!("$encryption${}${}", hmac_hex, encrypted);
    return Ok(formatted.to_string());
}
