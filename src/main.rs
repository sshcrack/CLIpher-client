use std::error::Error;

use base64;
use hex;
use libaes::Cipher;
use pbkdf2::{
    password_hash::{Ident, PasswordHasher, Salt},
    Params, Pbkdf2,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use substring::Substring;

const HMAC_KEY_SIZE: usize = 32;
const PASSWORD_KEY_SIZE: usize = 32;
const DERIVATION_ROUNDS: u32 = 200000;
const IV_LENGTH: usize = 16;
const SALT_LENGTH: usize = 12;
const FF_AS_NUMBER: u8 = 255;

type IvArr = [u8; IV_LENGTH];

fn main() {
    encrypt_text("My Text", "h");
}

fn encrypt_text(text: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let salt = "YJCTuo96N27C"; //generate_salt();
    let iv = generate_iv();
    let iv_hex = hex::encode(iv.to_vec());

    let derived_res = derive_from_password(password, &salt, DERIVATION_ROUNDS);
    if(derived_res.is_err()) {
        return Err(derived_res.unwrap_err().to_string());
    }
    let cipher = Cipher::new_256(raw_key);

    return Ok("");
}

fn generate_salt() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(SALT_LENGTH)
        .map(char::from)
        .collect()
}

fn generate_iv() -> IvArr {
    let mut rng = thread_rng();

    let mut arr = [0; IV_LENGTH];
    for a in 0..IV_LENGTH {
        arr[a] = rng.gen_range(0..FF_AS_NUMBER);
    }

    return arr;
}

#[derive(Debug)]
enum DeriveError {
    RoundError
}

#[derive(Debug)]
struct DeriveOutput {
    //Salt in plain form, not base64
    salt: String,

    //Key encoded in hex
    hex_key: String,

    //Rounds
    rounds: u32,

    //HMAC encoded in hex
    hex_hmac: String,

    //Bits of derive
    bits: usize,
}
fn derive_from_password(
    password: &str,
    salt_in: &str,
    rounds: u32,
) -> Result<DeriveOutput, Box<pbkdf2::password_hash::Error>> {
    let bits = (PASSWORD_KEY_SIZE + HMAC_KEY_SIZE) * 8;

    let pass_bytes = password.as_bytes();
    let salt_encoded = base64::encode(salt_in);

    if rounds <= 0 {
        return Err("Test");
    }

    let salt = Salt::new(&salt_encoded)?;
    let hash_parameter = Params {
        rounds: rounds,
        output_length: bits / 8,
    };

    let result = Pbkdf2.hash_password(
        pass_bytes,
        Some(Ident::new("pbkdf2-sha256")),
        hash_parameter,
        salt,
    )?;

    let hash = result.hash.unwrap();
    let bytes = hash.as_bytes();

    let hash_hex = hex::encode(bytes.to_vec());
    let hash_length = hash_hex.chars().count();

    let dhkEnd = hash_length / 2;

    let key = hash_hex.substring(0, dhkEnd);
    let hmac = hash_hex.substring(dhkEnd, hash_length);

    let key_raw = hex::decode(key)?;
    let hmac_raw = hex::decode(hmac)?;

    let out = DeriveOutput {
        salt: String::from(salt_in),
        hex_hmac: String::from(hmac),
        hex_key: String::from(key),
        bits: bits / 8,
        rounds,
    };
}
