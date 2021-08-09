mod constants;
mod encryption;
mod error;
mod generators;
mod utils;

use encryption::AES;

fn main() {
    AES::encrypt_text("My Text", "h");
}
