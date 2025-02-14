use argon2::PasswordHasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::Rng;
use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use threadpool::ThreadPool;
use walkdir::WalkDir;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncError {
    Read,
    Write,
    Encode,
    Decode,
    Key,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

/// Retrieves all file paths from a given folder.
///
/// # Arguments
/// * `folder` - A `PathBuf` representing the folder to search.
///
/// # Returns
/// * `Result<Vec<PathBuf>, EncError>` - A list of file paths if successful, otherwise an error.
fn get_files(folder: PathBuf) -> Result<Vec<PathBuf>, EncError> {
    let mut file_paths = Vec::new();
    for entry in WalkDir::new(folder) {
        let entry = entry.map_err(|_| EncError::Read)?;
        if entry.file_type().is_file() {
            file_paths.push(entry.path().to_path_buf());
        }
    }
    Ok(file_paths)
}

fn process_file(
    file_path: PathBuf,
    cipher: ChaCha20Poly1305,
    operation: Operation,
) -> Result<(), EncError> {
    let f = std::fs::read(&file_path);
    // Unreadable files are skipped
    if let Ok(f) = f {
        let (nonce, ciphertext) = match operation {
            Operation::Encrypt => {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let text = cipher.encrypt(&nonce, &*f).map_err(|_| EncError::Encode)?;
                (Some(nonce), text)
            }

            Operation::Decrypt => {
                let nonce = Nonce::from_slice(&f[..12]);
                let text = cipher
                    .decrypt(nonce, &f[12..])
                    .map_err(|_| EncError::Decode)?;
                (None, text)
            }
        };
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(file_path)
            .map_err(|_| EncError::Write)?;
        if let Some(nonce) = nonce {
            file.write_all(&nonce).map_err(|_| EncError::Write)?;
        }
        file.write_all(&ciphertext).map_err(|_| EncError::Write)?
    }
    Ok(())
}

pub fn check_decodable(path: PathBuf, cipher: ChaCha20Poly1305) -> bool {
    let files = get_files(path);
    if let Ok(files) = files {
        if !files.is_empty() {
            let mut rng = rand::thread_rng();
            let random_index = rng.gen_range(0..files.len());
            let file = &files[random_index];
            process_file(file.clone(), cipher, Operation::Decrypt).is_ok()
        } else {
            false
        }
    } else {
        false
    }
}

pub fn generate_key() -> ChaCha20Poly1305 {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    ChaCha20Poly1305::new(&key)
}

pub fn new_key(password: &str) -> Result<ChaCha20Poly1305, EncError> {
    let salt = argon2::password_hash::Salt::from_b64("azertyazerty").map_err(|_| EncError::Key)?;
    let argon2 = argon2::Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|_| EncError::Key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.hash.ok_or(EncError::Key)?.as_bytes())
        .map_err(|_| EncError::Key)?;
    Ok(cipher)
}

// Choose to panic if a mutex is poisoned as there is not recovery possible at
// this stage.
pub fn process_folder(
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    operation: Operation,
    on_progress: impl Fn(usize, usize) + Send + 'static + Clone,
) -> Result<(), EncError> {
    let files = get_files(path)?;

    let cipher = Arc::new(Mutex::new(cipher));
    let progress = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(Mutex::new(Vec::new()));
    let pool = ThreadPool::new(16);

    files.iter().cloned().for_each(|file| {
        let progress = Arc::clone(&progress);
        let cipher = Arc::clone(&cipher);
        let on_progress = on_progress.clone();
        let errors = errors.clone();
        let value = files.clone();

        pool.execute(move || {
            let cipher = cipher.lock().unwrap();
            let processed = progress.fetch_add(1, Ordering::SeqCst) + 1;
            on_progress(processed, value.len());
            errors
                .lock()
                .unwrap()
                .push(process_file(file, cipher.clone(), operation));
        });
    });

    pool.join();
    errors
        .lock()
        .unwrap()
        .iter()
        .find_map(|e| e.err())
        .map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, distributions::Alphanumeric};
    use std::{fs, fs::File, thread, time::Duration};

    #[cfg(test)]
    fn generate_dummy_file(file_path: &str, size: usize) -> Result<(), EncError> {
        let folder = file_path
            .split('/')
            .filter(|part| *part != ".")
            .next()
            .unwrap();
        fs::create_dir_all(format!("./{}", folder)).map_err(|_| EncError::Write)?;
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..size).map(|_| rng.r#gen()).collect();

        let mut file = File::create(file_path).map_err(|_| EncError::Write)?;
        file.write_all(&data).map_err(|_| EncError::Write)?;
        Ok(())
    }

    #[test]
    fn test_encryption_decryption() {
        let folder: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let cipher = generate_key();

        let mut originals = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            generate_dummy_file(name, 15).unwrap();
            originals.push(std::fs::read(name).unwrap());
        }

        process_folder(
            format!("./{}", folder).into(),
            cipher.clone(),
            Operation::Encrypt,
            |_, _| {},
        )
        .unwrap();

        let mut encrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            encrypteds.push(std::fs::read(name).unwrap());
        }
        assert_ne!(originals, encrypteds);

        process_folder(
            format!("./{}", folder).into(),
            cipher,
            Operation::Decrypt,
            |_, _| {},
        )
        .unwrap();

        let mut decrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            decrypteds.push(std::fs::read(name).unwrap());
        }
        assert_eq!(originals, decrypteds);

        fs::remove_dir_all(format!("./{}/", folder)).unwrap();
    }

    #[test]
    fn test_password_encryption_decryption() {
        let folder: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut originals = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            generate_dummy_file(name, 15).unwrap();
            originals.push(std::fs::read(name).unwrap());
        }

        let cipher = new_key("test").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher.clone(),
            Operation::Encrypt,
            |_, _| {},
        )
        .unwrap();

        let mut encrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            encrypteds.push(std::fs::read(name).unwrap());
        }
        assert_ne!(originals, encrypteds);

        let cipher = new_key("test2").unwrap();
        assert_eq!(
            process_folder(
                format!("./{}", folder).into(),
                cipher,
                Operation::Decrypt,
                |_, _| {}
            )
            .unwrap_err(),
            EncError::Decode
        );

        let cipher = new_key("test").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher,
            Operation::Decrypt,
            |_, _| {},
        )
        .unwrap();

        let mut decrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            decrypteds.push(std::fs::read(name).unwrap());
        }
        assert_eq!(originals, decrypteds);

        fs::remove_dir_all(format!("./{}/", folder)).unwrap();
    }

    #[test]
    fn test_folder_already_encrypted() {
        let folder: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut originals = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            generate_dummy_file(name, 15).unwrap();
            originals.push(std::fs::read(name).unwrap());
        }

        let cipher = new_key("test").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher.clone(),
            Operation::Encrypt,
            |_, _| {},
        )
        .unwrap();

        let mut encrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            encrypteds.push(std::fs::read(name).unwrap());
        }
        assert_ne!(originals, encrypteds);

        let cipher = new_key("test2").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher.clone(),
            Operation::Encrypt,
            |_, _| {},
        )
        .unwrap();

        let cipher = new_key("test2").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher.clone(),
            Operation::Decrypt,
            |_, _| {},
        )
        .unwrap();

        let cipher = new_key("test").unwrap();
        process_folder(
            format!("./{}", folder).into(),
            cipher,
            Operation::Decrypt,
            |_, _| {},
        )
        .unwrap();

        let mut decrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            decrypteds.push(std::fs::read(name).unwrap());
        }
        assert_eq!(originals, decrypteds);

        fs::remove_dir_all(format!("./{}/", folder)).unwrap();
    }

    #[test]
    fn test_folder_already_decrypted() {
        let folder: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut originals = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            generate_dummy_file(name, 15).unwrap();
            originals.push(std::fs::read(name).unwrap());
        }

        let cipher = new_key("test").unwrap();
        assert_eq!(
            process_folder(
                format!("./{}", folder).into(),
                cipher.clone(),
                Operation::Decrypt,
                |_, _| {},
            ),
            Err(EncError::Decode)
        );

        let mut decrypteds = Vec::new();
        for i in 0..10 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            decrypteds.push(std::fs::read(name).unwrap());
        }
        assert_eq!(originals, decrypteds);

        fs::remove_dir_all(format!("./{}/", folder)).unwrap();
    }

    #[test]
    fn test_folder_modified_during_exec() {
        let folder: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut originals = Vec::new();
        for i in 0..1_000 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            generate_dummy_file(name, 15).unwrap();
            originals.push(std::fs::read(name).unwrap());
        }

        let cipher_0 = new_key("test").unwrap();
        let folder_clone = folder.clone();
        let thread1 = thread::spawn(move || {
            process_folder(
                format!("./{}", folder_clone).into(),
                cipher_0,
                Operation::Encrypt,
                |_, _| {},
            )
            .unwrap();
        });

        let folder_clone = folder.clone();
        let thread2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            fs::remove_file(&format!("./{}/{}", folder_clone, 999)).unwrap();
        });

        thread1.join().unwrap();
        thread2.join().unwrap();

        let mut encrypteds = Vec::new();
        for i in 0..999 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            encrypteds.push(std::fs::read(name).unwrap());
        }
        assert_ne!(originals, encrypteds);

        let cipher = new_key("test").unwrap();
        let folder_clone = folder.clone();
        process_folder(
            format!("./{}", folder_clone).into(),
            cipher.clone(),
            Operation::Decrypt,
            |_, _| {},
        )
        .unwrap();

        let mut decrypteds = Vec::new();
        for i in 0..999 {
            let name = &format!("./{}/{}", folder, i).to_owned();
            decrypteds.push(std::fs::read(name).unwrap());
        }
        assert_eq!(originals[0..originals.len() - 1], decrypteds);

        fs::remove_dir_all(format!("./{}/", folder)).unwrap();
    }
}
