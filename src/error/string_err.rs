use core::fmt;
use std::error;

#[derive(Debug, Clone)]
pub struct StringErr {
    pub error: String,
}


impl fmt::Display for StringErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "Error ocurred: {}", self.error);
    }
}

impl error::Error for StringErr {}