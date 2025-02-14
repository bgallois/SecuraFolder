use license::LicenseManager;
/// This program generates a SecuraFolder's license.
///
/// It takes an email address as a command-line argument, generates a license key
/// using the provided `LicenseManager`, and then prints the generated key.
///
/// # Usage
/// To run the program, provide an email address as a command-line argument:
/// ```sh
/// cargo run <email_address>
/// ```
///
use securafolder::license;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mail = &args[1];
    let manager = license::Manager::<license::Hasher>::new(0);
    let key = manager.generate(mail);
    println!("{}", key);
}
