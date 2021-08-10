use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct HMACError {
    pub error: HMACEnum
}

#[derive(Debug, Clone)]
pub enum HMACEnum {
    InvalidKeyLength,
}


impl fmt::Display for HMACError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            HMACEnum::InvalidKeyLength => {
                return write!(f, "Invalid key length.")
            }
        }
    }
}

impl error::Error for HMACError {}