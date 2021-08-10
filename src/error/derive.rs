use core::fmt;
use std::error;


#[derive(Debug, Clone)]
pub struct DeriveError {
    pub error: DeriveEnum,
}

#[derive(Debug, Clone)]
pub enum DeriveEnum {
    RoundsInvalid
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.error {
            DeriveEnum::RoundsInvalid => {
                return write!(f, "Rounds are invalid")
            }
        }
    }
}

impl error::Error for DeriveError {}
