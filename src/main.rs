mod generators;
mod encryption;
mod constants;
mod packager;
mod error;
mod utils;

use encryption::aes;

use crate::packager::{unpackage_components};

fn main() {
    let str = "$AES_PASS_ENCRYPTOR$cbc,ac6dfd1c06dc7e9ed28b1fc1164ab3fe7c062a1ad56cded5de4cf8cb1050cd66,c39aae42241b6f5c405f6f5068ab282f,cAanLp36LQ03,200000$wjRLY9pSlNASmtkO6I/Y8g==";
    let res = aes::encrypt_text("My Text", "h");
    match res {
        Ok(res) => {
            let packaged = res.clone();
            let expected_res = unpackage_components(str);

            if expected_res.is_err() {
                return println!("Error occurred: {:#?}", expected_res.unwrap_err());
            }

            let expected = expected_res.unwrap();
            println!("Original: {:#?}", expected);
            println!("Res, {:#?} is same {}\nThis: {} Expected: {}", res, packaged == expected, res.encrypted, expected.encrypted)
        },
        Err(err) => {
            println!("Oh no, error {:#?}", err);
        }
    }
}
