mod constants;
mod encryption;
mod error;
mod generators;
mod packager;
mod utils;

use encryption::aes;

fn main() {
    let password = "h";

    let encrypt_res = aes::encrypt_text("My Text", password, None, None);
    match encrypt_res {
        Ok(encr_res) => {
            println!("Encrypted {}", encr_res);
            let decrypt_res = aes::decrypt_text(&encr_res, password);
            match decrypt_res {
                Ok(decrypt_text) => {
                    print!("Decrypted text: {}", decrypt_text);
                }
                Err(err) => {
                    println!("Oh no, error {:#?}", err);
                }
            }
        }
        Err(err) => {
            println!("Oh no, error {:#?}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        encryption::aes::{decrypt_text, encrypt_text},
        packager::unpackage_components,
    };
    const SERVER_SAMPLE: &str = "JEFFU19QQVNTX0VOQ1JZUFRPUiRjYmMsYWM2ZGZkMWMwNmRjN2U5ZWQyOGIxZmMxMTY0YWIzZmU3YzA2MmExYWQ1NmNkZWQ1ZGU0Y2Y4Y2IxMDUwY2Q2NixjMzlhYWU0MjI0MWI2ZjVjNDA1ZjZmNTA2OGFiMjgyZixjQWFuTHAzNkxRMDMsMjAwMDAwJHdqUkxZOXBTbE5BU210a082SS9ZOGc9PQ==";
    const PASSWORD: &str = "h";
    const TEXT: &str = "My Text";

    #[test]
    fn encrypt() {
        let unwrapped_res = unpackage_components(SERVER_SAMPLE);

        assert!(unwrapped_res.is_ok(), "Could not unpackage components");
        let unwrapped = unwrapped_res.unwrap();

        let res = encrypt_text(TEXT, PASSWORD, Some(unwrapped.salt), Some(unwrapped.iv));
        assert!(
            res.is_ok(),
            "Could not encrypt text. Error: {:#?}",
            res.unwrap_err()
        );

        let unwrapped_res = res.unwrap();
        assert_eq!(
            SERVER_SAMPLE, unwrapped_res,
            "Sample and generated are not the same."
        );
    }

    #[test]
    fn decrypt() {
        let decrypt_res = decrypt_text(SERVER_SAMPLE, PASSWORD);

        assert!(
            decrypt_res.is_ok(),
            "Could not decrypt text. Error: {:#?}",
            decrypt_res.unwrap_err()
        );

        let decrypted = decrypt_res.unwrap();
        assert_eq!(TEXT, decrypted, "Decrypted text does not match.");
    }
}
