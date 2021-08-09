use rand::{distributions::Alphanumeric, Rng, thread_rng};
use hex;
use pbkdf2::{Params, Pbkdf2, password_hash::{HasherError, Ident, ParseError, PasswordHasher, Salt}};

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

fn encrypt_text(text: &str, password: &str) {
    let salt = "YJCTuo96N27C";//generate_salt();
    let iv = generate_iv();
    let iv_hex = hex::encode(iv.to_vec());

    let derived_key = derive_from_password(
        password,
        &salt,
        DERIVATION_ROUNDS
    );

    match derived_key {
        Result::Err(e) => {
            println!("Error {:#?}", e);
        },
        Result::Ok(res) => {
            println!("Hex {} Salt {}", res, salt);
        }
    }
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
    };

    return arr;
}

#[derive(Debug)]
enum DeriveError {
    RoundError,
    ParseError(ParseError),
    HashError(HasherError)
}

fn derive_from_password(password: &str, salt: &str, rounds: u32) -> Result<String, DeriveError>{
    let bits = (PASSWORD_KEY_SIZE + HMAC_KEY_SIZE) * 8;
    let pass_bytes = password.as_bytes();
    let salt_res = Salt::new(salt);
    if salt_res.is_err() {
        return Err(DeriveError::ParseError(salt_res.unwrap_err()));
    }

    let salt_out = salt_res.unwrap();
    if rounds <= 0 {
        return Err(DeriveError::RoundError);
    }

    let password_hash = Pbkdf2.hash_password(pass_bytes, Some(Ident::new("pbkdf2-sha256")), None, Params {
        rounds: rounds,
        output_length: bits / 8,
    }, salt_out);


    match password_hash {
        Result::Err(e) => {
            Err(DeriveError::HashError(e))
        },
        Result::Ok(res) => {
            let hash = res.hash.unwrap();
            println!("Params {:#?}", res);

            let bytes =  hash.as_bytes();
            Ok(hex::encode(bytes.to_vec()))
        }
    }
}