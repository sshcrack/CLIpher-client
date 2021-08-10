use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct SaltError {}

impl fmt::Display for SaltError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "An Invalid salt was provided.")
    }
}

impl error::Error for SaltError {}