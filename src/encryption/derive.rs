use crate::{constants::*, utils::array::array_to_pass};
use substring::Substring;
use pbkdf2::{
    password_hash::{Error, Ident, PasswordHasher, Salt},
    Params, Pbkdf2,
};

#[derive(Debug)]
pub struct DeriveOutput {
    //Salt in plain form, not base64
    pub salt: String,

    //Key encoded in hex
    pub hex_key: String,
    pub hex_raw_key: [u8; PASSWORD_KEY_SIZE],
    pub raw_key: [u8; PASSWORD_KEY_SIZE],

    //Rounds
    pub rounds: u32,

    //HMAC encoded in hex
    pub hex_hmac: String,
    pub raw_hmac: [u8; PASSWORD_KEY_SIZE],
    pub hex_raw_hmac: [u8; PASSWORD_KEY_SIZE],

    //Bits of derive
    pub bits: usize,
}

#[derive(Debug, Clone)]
pub enum DeriveError {
    RoundsInvalid,
    SaltInvalid(Error),
    DeriveError(Error),
    InvalidHex,
}

pub fn derive_from_password(
    password: &str,
    salt_in: &str,
    rounds: u32,
) -> Result<DeriveOutput, DeriveError> {
    let bits = (PASSWORD_KEY_SIZE + HMAC_KEY_SIZE) * 8;

    let pass_bytes = password.as_bytes();
    let salt_encoded = base64::encode(salt_in);

    if rounds <= 0 {
        return Err(DeriveError::RoundsInvalid);
    }

    let salt_res = Salt::new(&salt_encoded);
    if salt_res.is_err() {
        return Err(DeriveError::SaltInvalid(salt_res.unwrap_err()));
    }

    let salt = salt_res.unwrap();
    let hash_parameter = Params {
        rounds: rounds,
        output_length: bits / 8,
    };

    let result_err = Pbkdf2.hash_password(
        pass_bytes,
        Some(Ident::new("pbkdf2-sha256")),
        hash_parameter,
        salt,
    );
    if result_err.is_err() {
        return Err(DeriveError::DeriveError(result_err.unwrap_err()));
    }

    let result = result_err.unwrap();
    let hash = result.hash.unwrap();
    let bytes = hash.as_bytes();

    let hash_hex = hex::encode(bytes.to_vec());
    let hash_length = hash_hex.chars().count();

    let dhk_end = hash_length / 2;

    let key = hash_hex.substring(0, dhk_end).to_string();
    let hmac = hash_hex.substring(dhk_end, hash_length).to_string();

    let key_raw_res = hex::decode(key.clone());
    let hmac_raw_res = hex::decode(hmac.clone());

    if key_raw_res.is_err() || hmac_raw_res.is_err() {
        return Err(DeriveError::InvalidHex);
    }
    let key_raw = key_raw_res.unwrap();
    let hmac_raw = hmac_raw_res.unwrap();

    let key_iter = key_raw.iter();
    let hmac_iter = hmac_raw.iter();

    let key_bytes = array_to_pass(key_iter);
    let hmac_bytes = array_to_pass(hmac_iter);

    let out = DeriveOutput {
        salt: String::from(salt_in),
        bits: bits / 8,
        rounds,

        hex_hmac: hmac.clone(),
        hex_raw_hmac: array_to_pass(hmac.as_bytes().iter()),
        raw_hmac: hmac_bytes,

        hex_key: key.clone(),
        hex_raw_key: array_to_pass(key.as_bytes().iter()),
        raw_key: key_bytes,
    };

    return Ok(out);
}
