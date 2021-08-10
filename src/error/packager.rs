use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct PackageError {
    pub error: PackageEnum
}

#[derive(Debug, Clone)]
pub enum PackageEnum {
    InvalidIdentifier,
    InvalidComponents,
    InvalidRounds,
    WrongStart
}


impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            PackageEnum::InvalidIdentifier => {
                return write!(f, "Invalid string to unpack given.")
            },
            PackageEnum::InvalidComponents => {
                return write!(f, "Invalid components length")
            },
            PackageEnum::InvalidRounds => {
                return write!(f, "Could not parse rounds")
            },
            PackageEnum::WrongStart => {
                return write!(f, "Started with wrong character")
            }
        }
    }
}

impl error::Error for PackageError {}