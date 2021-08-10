use hmac::crypto_mac::InvalidKeyLength;

use core::fmt;
use std::error;

use super::derive::*;

#[derive(Debug, Clone)]
pub struct EncryptError {
    pub derive: Option<DeriveError>,
    pub hmac: Option<InvalidKeyLength>
}


impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.derive.is_some() {
            let derive_ref = self.derive.as_ref().unwrap();
            let err = &derive_ref.error;

            match err {
                DeriveEnum::RoundsInvalid => {
                    return write!(f, "Rounds given are invalid")
                }
            }
        }

        if self.hmac.is_some() {
            return write!(f, "Invalid key length.")
        }

        return write!(f, "Unknown error occurred.")
    }
}

impl error::Error for EncryptError {}