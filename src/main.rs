#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;

mod encryption;

slint::include_modules!();
fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;
    ui.on_submit({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            let password = ui.get_pass();
            let is_encrypting = ui.get_is_encrypting();
            println!("Password: {}", password);
            println!("Checkbox checked: {}", is_encrypting);
            for i in 0..10000 {
                ui.set_progress((i / 1000) as f32);
            }
        }
    });
    ui.run()?;
    Ok(())
}
