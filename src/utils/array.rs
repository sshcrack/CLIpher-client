use std::{slice::Iter, str};

use crate::constants::*;


pub fn array_to_pass(mut iter: Iter<u8>) -> [u8; PASSWORD_KEY_SIZE] {
    let mut arr = [0; PASSWORD_KEY_SIZE];

    for i in 0..PASSWORD_KEY_SIZE {
        arr[i] = *iter.next().unwrap();
    }

    return arr;
}