#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{env, error::Error, fs, path::Path};

mod encryption;

slint::include_modules!();
fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;
    init(&ui)?;

    ui.on_submit({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            let password = ui.get_pass();
            let is_encrypted = ui.get_is_encrypted();
            for i in 0..10000 {
                ui.set_progress((i / 1000) as f32);
            }
        }
    });

    ui.run()?;
    Ok(())
}

fn init(ui: &AppWindow) -> Result<(), Box<dyn Error>> {
    let path = env::current_exe()?
        .parent()
        .ok_or("Failed to get the parent directory")?
        .join("Secura");
    println!("{:?}", path);
    match fs::create_dir(path) {
        Ok(()) => {
            ui.set_is_encrypted(false);
            Ok(())
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            ui.set_is_encrypted(true);
            println!("alreadyexist");
            Ok(())
        }
        Err(err) => {
            ui.set_is_encrypted(false);
            println!("alreadyexist");
            Err(err)?
        }
    }
}
