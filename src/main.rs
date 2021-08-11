use std::collections::HashMap;

use encryption::rsa;
use reqwest::Client;
use serde_json::Value;
use std::error::Error;
use tokio::runtime::Runtime;

use crate::api_structures::EncryptionKey;

mod api_structures;
mod constants;
mod encryption;
mod enums;
mod error;
mod generators;
mod packager;
mod utils;

fn main() {
    let mut rt = Runtime::new().unwrap();
    let future = app();
    rt.block_on(future);
}

async fn app() -> Result<(), Box<dyn Error>> {
    let username = "sshcrack";
    let client = Client::default();
    let mut body = HashMap::new();
    body.insert("username", username);

    let text = client
        .post("http://localhost:3000/api/register/getEncryptionKey")
        .json(&body)
        .send()
        .await?
        .text()
        .await?;

    let json: Value = serde_json::from_str(&text)?;
    let err = json["message"].as_str();

    if err.is_some() {
        println!("Error getting encryption key {}", err.unwrap());
        return Ok(());
    }

    let res: EncryptionKey = serde_json::from_value(json)?;
    let key = res.public_key;

    let encrypted = rsa::encrypt(&key, "Test hehe")?;
    let hex_encrypted = hex::encode(encrypted);

    println!("Encrypted hex {}", hex_encrypted);
    let url = format!(
        "http://localhost:3000/api/rsa?username={}&hex={}",
        username, hex_encrypted
    );
    let decrypt_text = client.get(url).send().await?.text().await?;

    println!("Decrypted {}", decrypt_text);
    return Ok(());
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
