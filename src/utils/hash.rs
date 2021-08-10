use pbkdf2::{
    password_hash::{Ident, PasswordHasher, Salt},
    Params, Pbkdf2,
};
use std::error::Error;
use substring::Substring;

use crate::{constants::PASSWORD_KEY_SIZE, error::hash::HashError};

use super::array::to_pass_arr;

pub fn hash_password<'a>(
    password: &[u8],
    algorithm: Option<Ident<'a>>,
    params: Params,
    salt: Salt<'a>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let result = Pbkdf2.hash_password(password, algorithm, params, salt);

    if result.is_err() {
        return Err(Box::new(HashError {}));
    }

    let hash = result.unwrap().hash.unwrap();
    let bytes = hash.as_bytes().to_vec();

    return Ok(bytes);
}

pub fn extract_hashes(hash: &[u8]) -> Result<HashExtract, Box<dyn Error>> {
    let hash_hex = hex::encode(hash.to_vec());

    let hash_length = hash_hex.chars().count();
    let dhk_length = hash_length / 2;

    let key_hex = hash_hex.substring(0, dhk_length);
    let key_hex_bytes = key_hex.as_bytes();

    let hmac_hex = hash_hex.substring(dhk_length, hash_length);
    let hmac_hex_bytes = hmac_hex.as_bytes();

    let key_decoded = hex::decode(key_hex.clone())?;
    let hmac_decoded = hex::decode(hmac_hex.clone())?;

    let raw_key = to_pass_arr(key_decoded.iter());
    let raw_hmac = to_pass_arr(hmac_decoded.iter());

    return Ok(HashExtract {
        hmac: SingleHash {
            hex: hmac_hex.to_string(),
            hex_bytes: hmac_hex_bytes.to_vec(),
            raw: raw_hmac,
        },
        key: SingleHash {
            hex: key_hex.to_string(),
            hex_bytes: key_hex_bytes.to_vec(),
            raw: raw_key,
        },
    });
}

#[derive(Debug)]
pub struct HashExtract {
    pub key: SingleHash,
    pub hmac: SingleHash,
}

#[derive(Debug)]
pub struct SingleHash {
    pub hex: String,
    pub hex_bytes: Vec<u8>,
    pub raw: [u8; PASSWORD_KEY_SIZE],
}
