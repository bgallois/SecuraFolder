use securafolder::license;

use license::LicenseManager;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mail = &args[1];
    let manager = license::Manager::<license::Hasher>::new(0);
    let key = manager.generate(mail);
    println!("{}", key);
}
