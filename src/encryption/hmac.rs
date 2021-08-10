use crate::{
    constants::*,
    error::hmac::{HMACEnum, HMACError},
};
use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;
use std::error::Error;

type HmacSha256 = Hmac<Sha256>;
pub fn getHMAC<'a>(input: HmacInput<'a>) -> Result<String, Box<dyn Error>> {
    let hmac_tool_res = HmacSha256::new_from_slice(input.key);
    if hmac_tool_res.is_err() {
        return Err(Box::new(HMACError {
            error: HMACEnum::InvalidKeyLength,
        }));
    }

    let tool = hmac_tool_res.unwrap();

    tool.update(input.encrypted.as_bytes());
    tool.update(input.iv.as_bytes());
    tool.update(input.salt.as_bytes());

    let out_bytes = tool.finalize().into_bytes();
    let hex = hex::encode(out_bytes);
    return Ok(hex);
}

pub struct HmacInput<'a> {
    /* HMAC Array */
    key: &'a [u8; PASSWORD_KEY_SIZE],

    /*The encrypted content */
    encrypted: &'a str,

    /* Initialization Vector as Hex */
    iv: &'a str,

    /* The Salt as plain text */
    salt: &'a str,
}
