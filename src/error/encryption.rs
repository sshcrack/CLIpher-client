use hmac::crypto_mac::InvalidKeyLength;

use crate::encryption::derive::DeriveError;
use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct EncryptError {
    pub derive: Option<DeriveError>,
    pub hmac: Option<InvalidKeyLength>
}


impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.derive.is_some() {
            let err = self.derive.as_ref().unwrap();
            match err {
                DeriveError::SaltInvalid(err) => {
                    return write!(f, "Salt invalid: {:#?}", err)
                }
                DeriveError::RoundsInvalid => {
                    return write!(f, "Rounds given are invalid")
                }
                DeriveError::DeriveError(err) => {
                    return write!(f, "Couldn't derive: {:#?}", err)
                }
                DeriveError::InvalidHex => {
                    return write!(f, "Couldn't decode hex.")
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