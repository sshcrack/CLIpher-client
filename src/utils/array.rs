use std::{slice::Iter};

use crate::constants::*;


pub fn to_pass_arr(mut iter: Iter<u8>) -> [u8; PASSWORD_KEY_SIZE] {
    let mut arr = [0; PASSWORD_KEY_SIZE];

    for i in 0..PASSWORD_KEY_SIZE {
        arr[i] = *iter.next().unwrap();
    }

    return arr;
}