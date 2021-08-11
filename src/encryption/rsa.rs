use openssl::rsa::{Padding, Rsa};
use std::error::Error;
use std::str;

pub fn encrypt(pub_key_pem: &str, msg: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = Rsa::public_key_from_pem(pub_key_pem.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; key.size() as usize];

    let size = key.public_encrypt(
        &msg.as_bytes(),
        &mut buf,
        Padding::PKCS1_OAEP
    )?;

    let mut out = vec![0; size];
    for i in 0..size {
        out[i] = buf[i];
    }

    return Ok(out);
}

pub fn decrypt(priv_key_pem: &str, cipher: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = Rsa::private_key_from_pem(priv_key_pem.as_bytes())?;
    let mut buf: Vec<u8> = vec![0; key.size() as usize];

    let size = key.private_decrypt(
        &cipher,
        &mut buf,
        Padding::PKCS1_OAEP
    )?;

    let mut out = vec![0; size];
    for i in 0..size {
        out[i] = buf[i];
    }

    return Ok(out);
}
