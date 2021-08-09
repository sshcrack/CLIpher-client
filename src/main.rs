mod constants;
mod encryption;
mod error;
mod generators;
mod utils;

use encryption::aes;

fn main() {
    let res = aes::encrypt_text("My Text", "h");
    match res {
        Ok(res) => {
            println!("Res, {}", res)
        },
        Err(err) => {
            println!("Oh no, error {:#?}", err);
        }
    }
}
