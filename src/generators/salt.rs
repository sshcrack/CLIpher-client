use rand::{Rng, distributions::Alphanumeric};

use crate::constants::*;

#[allow(dead_code)]
pub fn generate_salt() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(SALT_LENGTH)
        .map(char::from)
        .collect()
}