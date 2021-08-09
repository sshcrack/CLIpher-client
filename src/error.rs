use crate::encryption::derive::DeriveError;
use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct EncryptError {
    pub error: DeriveError,
}


impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            DeriveError::SaltInvalid(err) => {
                write!(f, "Salt invalid: {:#?}", err)
            }
            DeriveError::RoundsInvalid => {
                write!(f, "Rounds given are invalid")
            }
            DeriveError::DeriveError(err) => {
                write!(f, "Couldn't derive: {:#?}", err)
            }
            DeriveError::InvalidHex => {
                write!(f, "Couldn't decode hex.")
            }
        }
    }
}

impl error::Error for EncryptError {}
