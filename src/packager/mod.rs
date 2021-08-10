use std::error::Error;
use crate::constants::*;
use crate::error::packager::*;


#[allow(dead_code)]
pub fn package_components(components: PackageComponents) -> String {
    let PackageComponents { method, hmac, iv, salt, rounds, encrypted } = components;

    return format!("${}${},{},{},{},{}${}", IDENTIFIER, method, hmac, iv, salt, rounds, encrypted).to_string()
}

pub fn unpackage_components(raw: &str) -> Result<PackageComponents, Box<dyn Error>> {
    if !raw.starts_with("$") {
        return Err(Box::new(
            PackageError {
                error: PackageEnum::WrongStart
            }
        ))
    }
    let split: Vec<&str> = raw.split("$").skip(1).collect();

    let str_identifier = split.first();
    if str_identifier.ne(&Some(&IDENTIFIER)) {
        return Err(Box::new(
            PackageError {
                error: PackageEnum::InvalidIdentifier
            }
        ));
    }

    let packaged = split.get(1).expect("Packaged components not found");
    let encrypted = split.last().expect("Encrypted message not found.");

    let split_components: Vec<&str> = packaged.split(",").collect();
    if split_components.len() != 5 {
        return Err(Box::new(
            PackageError {
                error: PackageEnum::InvalidComponents
            }
        ));
    }

    if let [ method, hmac, iv, salt, rounds ] = split_components.as_slice() {
        let rounds_int = rounds.parse::<u32>();
        if rounds_int.is_err() {
            return Err(Box::new(
                PackageError {
                    error: PackageEnum::InvalidRounds
                }
            ));
        }

        return Ok(PackageComponents {
            encrypted: encrypted.to_string(),
            hmac: hmac.to_string(),
            iv: iv.to_string(),
            method: method.to_string(),
            rounds: rounds_int.unwrap(),
            salt: salt.to_string()
        })
    }

    return Err(Box::new(
        PackageError {
            error: PackageEnum::InvalidComponents
        }
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageComponents {
    //Method
    pub method: String,

    //HMAC as hex
    pub hmac: String,

    //Initialization vector as hex
    pub iv: String,

    //Salt as plain text
    pub salt: String,

    //Derivation rounds
    pub rounds: u32,

    pub encrypted: String
}