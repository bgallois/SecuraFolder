#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// This program provides a user interface for encrypting and decrypting files using a password.
/// The application interacts with the user via a UI, processes folder encryption/decryption,
/// and handles license verification for larger file support.
///
/// # Features
/// - Encrypts and decrypts a folder of files.
/// - Verifies if a user has a valid license for larger folders.
/// - Displays progress and error messages during the encryption/decryption process.
/// - Locks and unlocks the UI based on the encryption state.
///
/// # Usage
/// 1. The program initializes by checking if the "Secura" folder exists. If it doesn't, it creates it.
/// 2. On submission, the program either encrypts or decrypts the folder depending on its current state.
/// 3. Progress is displayed on the UI in real-time, and the UI is locked during the encryption/decryption process.
/// 4. The program ensures that a valid license is in place for larger folders before proceeding with encryption.
use securafolder::encryption;
use std::{env, error::Error, fs, path::PathBuf, sync::mpsc, thread};
#[cfg(feature = "limited")]
use {fs_extra::dir::get_size, license::LicenseManager, securafolder::license, std::path::Path};

#[cfg(feature = "limited")]
const SIZE: u64 = 5_242_880;

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
                match process(
                    ui.as_weak(),
                    path.clone(),
                    &password,
                    encryption::Operation::Encrypt,
                ) {
                    Ok(()) => ui.set_is_encrypted(!is_encrypted),
                    Err(_) => ui.set_is_encrypted(is_encrypted),
                }
            } else {
                match process(
                    ui.as_weak(),
                    path.clone(),
                    &password,
                    encryption::Operation::Decrypt,
                ) {
                    Ok(()) => ui.set_is_encrypted(!is_encrypted),
                    Err(_) => ui.set_is_encrypted(is_encrypted),
                }
            }
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

/// Initializes the "Secura" folder and sets the encryption state on the UI.
///
/// - If the folder doesn't exist, it is created, and the encryption state is set to false (not encrypted).
/// - If the folder already exists, the encryption state is set to true (encrypted).
/// - If an error occurs while creating the folder, the encryption state is set to false, and the error is returned.
///
/// # Parameters
/// - `ui`: The user interface instance to update the encryption state.
/// - `path`: The path of the folder to check/create.
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

/// Processes folder encryption or decryption based on the specified operation.
///
/// This function handles license validation, ensures the folder's size does not exceed free limits,
/// and performs encryption or decryption in a separate thread. Progress is sent to the UI, and
/// the UI is locked during processing.
///
/// # Parameters
/// - `ui`: Weak reference to the user interface for progress and state updates.
/// - `path`: The path to the folder being processed.
/// - `password`: The password used for encryption or decryption.
/// - `operation`: The encryption or decryption operation to perform.
fn process(
    ui: slint::Weak<AppWindow>,
    path: PathBuf,
    password: &str,
    operation: encryption::Operation,
) -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "limited")]
    if get_size(&path)? > SIZE {
        let ui = ui.unwrap();
        ui.set_lock(false);
        if let Ok(key) = fs::read_to_string(
            path.parent()
                .unwrap_or_else(|| Path::new(""))
                .join("key.txt"),
        ) {
            let manager = license::Manager::<license::Hasher>::new(0);
            match manager.verify(&key) {
                license::Status::Valid => (),
                _ => {
                    ui.invoke_msg("Invalid license".into());
                    return Err("NotDecodable".into());
                }
            }
        } else {
            ui.invoke_msg(
    "The folder size exceeds the 5 MiB limit included with the free version. To unlock larger folder support, please place a valid 'key.txt' file in the same folder as the executable.".into(),
);
            return Err("NotDecodable".into());
        }
    }

    let cipher = encryption::new_key(password).map_err(|_| "Error")?;
    let (tx, rx) = mpsc::channel();

    if operation == encryption::Operation::Decrypt
        && !encryption::check_decodable(path.clone(), cipher.clone())
    {
        let ui = ui.unwrap();
        ui.set_lock(false);
        ui.invoke_msg(
            "Incorrect password or unencrypted Secura folder (see the user manual).".into(),
        );
        return Err("NotDecodable".into());
    }

    thread::spawn(move || {
        let _ = encryption::process_folder(path, cipher, operation, move |i, total| {
            tx.send((i, total)).expect("Failed to send progress");
        });
    });

    thread::spawn(move || {
        for (i, total) in rx {
            let ui_clone = ui.clone();
            let progress = i as f32 / total as f32;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_clone.upgrade() {
                    match operation {
                        encryption::Operation::Encrypt => ui.set_progress(1f32 - progress),
                        encryption::Operation::Decrypt => ui.set_progress(progress),
                    }
                }
            })?;
        }
        slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui.upgrade() {
                ui.set_lock(false);
            }
        })
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, distributions::Alphanumeric};
    use std::{fs::File, io::Write};

    // One test due to set_platform error.
    #[test]
    fn test_limit() -> Result<(), Box<dyn std::error::Error>> {
        let path: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let ui = AppWindow::new()?;
        init(&ui, path.clone().into())?;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..SIZE).map(|_| rng.r#gen()).collect();

        let mut file = File::create(format!("./{}/SecuraFolder", path))?;
        file.write_all(&data)?;

        assert!(
            process(
                ui.as_weak(),
                format!("./{}/SecuraFolder", path).into(),
                "test",
                encryption::Operation::Encrypt
            )
            .is_ok()
        );

        fs::remove_dir_all(format!("./{}/", path)).unwrap();

        let path: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let ui = AppWindow::new()?; // Good in one test but fail if recall in another
        init(&ui, path.clone().into())?;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..SIZE + 1).map(|_| rng.r#gen()).collect();

        let mut file = File::create(format!("./{}/SecuraFolder", path))?;
        file.write_all(&data)?;

        assert!(
            process(
                ui.as_weak(),
                format!("./{}/SecuraFolder", path).into(),
                "test",
                encryption::Operation::Encrypt
            )
            .is_err()
        );

        let mut file = File::create(format!("./{}/key.txt", path))?;
        file.write_all("b2b0db5a1b7d6b7352f27e83e4f12b00274a71e61ac5e59958dd05".as_bytes())?;
        assert!(
            process(
                ui.as_weak(),
                format!("./{}/SecuraFolder", path).into(),
                "test",
                encryption::Operation::Encrypt
            )
            .is_err()
        );

        let mut file = File::create(format!("./{}/key.txt", path))?;
        file.write_all("b2b0db5a1b7d6b7352f27e83e4f9712b00274a71e61ac5e59958dd05".as_bytes())?;
        assert!(
            process(
                ui.as_weak(),
                format!("./{}/SecuraFolder", path).into(),
                "test",
                encryption::Operation::Encrypt
            )
            .is_ok()
        );

        fs::remove_dir_all(format!("./{}/", path)).unwrap();
        Ok(())
    }
}
