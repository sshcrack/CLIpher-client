use std::error::Error;
use std::str;
use libaes::Cipher;
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};

use crate::encryption::hmac::{HmacInput, getHMAC};
use crate::packager::{PackageComponents};
use crate::{constants::*};
use crate::{ error::encryption::EncryptError };
use super::derive::derive_from_password;

type HmacSha256 = Hmac<Sha256>;
pub fn encrypt_text(text: &str, password: &str) -> Result<PackageComponents, Box<dyn Error>> {
    let salt = "cAanLp36LQ03"; //generate_salt();
    let iv = hex::decode("c39aae42241b6f5c405f6f5068ab282f")?;//generate_iv();
    let iv_hex = hex::encode(iv.to_vec());

    let derived_res = derive_from_password(password, &salt, DERIVATION_ROUNDS);
    if derived_res.is_err() {
        let err = derived_res.unwrap_err();
        return Err(Box::new(EncryptError {
            derive: Some(err),
            hmac: None
        }));
    }

    let derived = derived_res.unwrap();

    let cipher = Cipher::new_256(&derived.raw_key);
    let hmac_tool_res = HmacSha256::new_from_slice(&derived.raw_hmac);
    if hmac_tool_res.is_err() {
        let err = hmac_tool_res.unwrap_err();
        return Err(Box::new(EncryptError {
            derive: None,
            hmac: Some(err)
        }))
    }

    let mut hmac_tool = hmac_tool_res.unwrap();

    let encrypted_raw = cipher.cbc_encrypt(&iv, text.as_bytes());
    let encrypted: String = base64::encode(&encrypted_raw);

    hmac_tool.update(&encrypted.as_bytes());
    hmac_tool.update(iv_hex.as_bytes());
    hmac_tool.update(salt.as_bytes());

    let hmac_hex_bytes = hmac_tool.finalize().into_bytes();

    let hmac_hex = hex::encode(hmac_hex_bytes);

    let hmac_hex = getHMAC(HmacInput {
        encrypted: 
    })
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
