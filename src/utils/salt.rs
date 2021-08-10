use pbkdf2::password_hash::Salt;

use crate::error::salt::SaltError;

/* Salt parameter should not be enocded in base64, use utf8 encoding */
pub fn gen_salt<'a>(salt_b64: &'a str) -> Result<Salt<'a>, SaltError> {
    let salt_res = Salt::<'a>::new(salt_b64);

    if salt_res.is_err() {
        return Err(SaltError {})
    }

    return Ok(salt_res.unwrap());
}