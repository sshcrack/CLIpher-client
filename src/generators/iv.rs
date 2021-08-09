use rand::{Rng, thread_rng};

use crate::constants::*;

pub type IvArr = [u8; IV_LENGTH];
pub fn generate_iv() -> IvArr {
    let mut rng = thread_rng();

    let mut arr = [0; IV_LENGTH];
    for a in 0..IV_LENGTH {
        arr[a] = rng.gen_range(0..FF_AS_NUMBER);
    }

    return arr;
}