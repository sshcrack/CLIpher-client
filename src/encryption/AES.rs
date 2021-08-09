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

    println!("Deriving...");
    let derived_res = derive_from_password(password, &salt, DERIVATION_ROUNDS);
    if derived_res.is_err() {
        let err = derived_res.unwrap_err();
        return Err(Box::new(EncryptError {
            derive: Some(err),
            hmac: None
        }));
    }

    let derived = derived_res.unwrap();

    println!("Creating cipher and hmac...");
    let cipher = Cipher::new_256(&derived.hex_raw_key);
    let hmac_tool_res = HmacSha256::new_from_slice(&derived.hex_raw_hmac);
    if hmac_tool_res.is_err() {
        let err = hmac_tool_res.unwrap_err();
        return Err(Box::new(EncryptError {
            derive: None,
            hmac: Some(err)
        }))
    }

    let mut hmac_tool = hmac_tool_res.unwrap();
    println!("Encrypting...");
    let encrypted_raw = cipher.cbc_encrypt(&iv, text.as_bytes());
    println!("From utf8... \n{:#?}", encrypted_raw);

    let encrypted: String = base64::encode(&encrypted_raw);

    println!("Updating...");
    hmac_tool.update(&encrypted_raw);
    hmac_tool.update(iv_hex.as_bytes());
    hmac_tool.update(salt.as_bytes());

    let hmac_hex_bytes = hmac_tool.finalize().into_bytes();
    println!("From utf2...");
    let hmac_hex = hex::encode(hmac_hex_bytes);

    println!("Formatting...");
    let formatted = format!("$AES_PASS_ENCRYPTOR${},{},{},{},{}${}", ENCRYPTION_METHOD, hmac_hex, iv_hex, salt, DERIVATION_ROUNDS, encrypted);

    println!("Ok");
    return Ok(formatted.to_string());
}
