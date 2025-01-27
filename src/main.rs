#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::{
    env,
    error::Error,
    fs,
    path::PathBuf,
    sync::mpsc,
    thread,
};

mod encryption;

slint::include_modules!();
fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;
    let path = env::current_exe()?
        .parent()
        .ok_or("Failed to get the parent directory")?
        .join("Secura");
    init(&ui, path.clone())?;

    ui.on_submit({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            let password = ui.get_pass();
            let is_encrypted = ui.get_is_encrypted();
            if !is_encrypted {
                match encrypt(ui.as_weak(), path.clone(), &password) {
                    Ok(()) => ui.set_is_encrypted(!is_encrypted),
                    Err(_) => ui.set_is_encrypted(is_encrypted),
                }
            } else {
                match decrypt(ui.as_weak(), path.clone(), &password) {
                    Ok(()) => ui.set_is_encrypted(!is_encrypted),
                    Err(_) => ui.set_is_encrypted(is_encrypted),
                }
            }
            ui.set_lock(false);
        }
    });

    ui.window().on_close_requested({
        let ui_handle = ui.as_weak();
        move || {
            let ui = ui_handle.unwrap();
            ui.invoke_close_requested();
            if !ui.get_is_encrypted() {
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                slint::CloseRequestResponse::HideWindow
            }
        }
    });

    ui.run()?;
    Ok(())
}

fn init(ui: &AppWindow, path: PathBuf) -> Result<(), Box<dyn Error>> {
    match fs::create_dir(path) {
        Ok(()) => {
            ui.set_is_encrypted(false);
            Ok(())
        }
        Err(ref err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            ui.set_is_encrypted(true);
            Ok(())
        }
        Err(err) => {
            ui.set_is_encrypted(false);
            Err(err)?
        }
    }
}

fn encrypt(
    ui: slint::Weak<AppWindow>,
    path: PathBuf,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let (nonce, cipher) = encryption::new_key(password).map_err(|_| "Error")?;
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        encryption::process_folder(
            path,
            nonce,
            cipher,
            encryption::Operation::Encrypt,
            move |i, total| {
                tx.send((i, total)).expect("Failed to send progress");
            },
        )
    });

    thread::spawn(move || {
        for (i, total) in rx {
            let ui_clone = ui.clone();
            let progress = i as f32 / total as f32;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_clone.upgrade() {
                    ui.set_progress(1f32 - progress);
                }
            })
            .unwrap();
        }
    });
    Ok(())
}

fn decrypt(
    ui: slint::Weak<AppWindow>,
    path: PathBuf,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let (nonce, cipher) = encryption::new_key(password).map_err(|_| "Error")?;
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        encryption::process_folder(
            path,
            nonce,
            cipher,
            encryption::Operation::Decrypt,
            move |i, total| {
                tx.send((i, total)).expect("Failed to send progress");
            },
        )
    });

    thread::spawn(move || {
        for (i, total) in rx {
            let ui_clone = ui.clone();
            let progress = i as f32 / total as f32;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_clone.upgrade() {
                    ui.set_progress(progress);
                }
            })
            .unwrap();
        }
    });
    Ok(())
}
