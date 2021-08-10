use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct DecryptError {
    pub error: DecryptEnum,
}

#[derive(Debug, Clone)]
pub enum DecryptEnum {
    HmacMismatch,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            DecryptEnum::HmacMismatch => {
                return write!(f, "HMAC mismatch");
            }
        }
    }
}

impl error::Error for DecryptError {}
