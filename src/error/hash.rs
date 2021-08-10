use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct HashError {}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An error occurred during hashing.")
    }
}

impl error::Error for HashError {}