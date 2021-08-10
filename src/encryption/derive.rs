use crate::{constants::*, error::derive::*, utils::{hash::{HashExtract, extract_hashes, hash_password}, salt::gen_salt}};
use pbkdf2::{
    password_hash::Ident,
    Params,
};
use std::error::Error;

#[derive(Debug)]
pub struct DeriveOutput {
    //Salt in plain form, not base64
    pub salt: String,

    //Rounds
    pub rounds: u32,
    //Bits of derive
    pub bits: usize,

    //Extracted keys
    pub extracted: HashExtract
}

pub fn derive_from_password(
    password: &str,
    salt_in: &str,
    rounds: u32,
) -> Result<DeriveOutput, Box<dyn Error>> {
    let bits = (PASSWORD_KEY_SIZE + HMAC_KEY_SIZE) * 8;
    if rounds <= 0 {
        return Err(Box::new(DeriveError {
            error: DeriveEnum::RoundsInvalid,
        }));
    }

    let pass_bytes = password.as_bytes();

    let b64_salt = base64::encode(salt_in);
    let salt = gen_salt(&b64_salt)?;

    let hash = hash_password(
        pass_bytes.into(),
        Some(Ident::new("pbkdf2-sha256")),
        Params {
            rounds: rounds,
            output_length: bits / 8,
        },
        salt,
    )?;

    let keys = extract_hashes(&hash)?;

    let out = DeriveOutput {
        salt: String::from(salt_in),
        bits: bits / 8,
        rounds,
        extracted: keys
    };

    return Ok(out);
}
