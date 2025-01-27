use argon2::PasswordHasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use std::{
    fs::{OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};
use walkdir::WalkDir;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncError {
    Read,
    Write,
    Encode,
    Decode,
    Key,
}

#[derive(Copy, Clone, Debug)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

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
    nonce: Nonce,
    cipher: ChaCha20Poly1305,
    operation: Operation,
) -> Result<(), EncError> {
    let f = std::fs::read(&file_path).map_err(|_| EncError::Read)?;
    let ciphertext = match operation {
        Operation::Encrypt => cipher.encrypt(&nonce, &*f).map_err(|_| EncError::Encode)?,
        Operation::Decrypt => cipher.decrypt(&nonce, &*f).map_err(|_| EncError::Decode)?,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_path)
        .map_err(|_| EncError::Write)?;
    file.write_all(&ciphertext).map_err(|_| EncError::Write)?;
    Ok(())
}

pub fn _generate_key() -> (Nonce, ChaCha20Poly1305) {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    (nonce, cipher)
}

pub fn new_key(password: &str) -> Result<(Nonce, ChaCha20Poly1305), EncError> {
    let salt = argon2::password_hash::Salt::from_b64("azertyazerty").map_err(|_| EncError::Key)?;
    let argon2 = argon2::Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|_| EncError::Key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.hash.unwrap().as_bytes())
        .map_err(|_| EncError::Key)?;
    let nonce = chacha20poly1305::aead::generic_array::GenericArray::from_slice(&[0u8; 12]);
    Ok((*nonce, cipher))
}

pub fn process_folder(
    path: PathBuf,
    nonce: Nonce,
    cipher: ChaCha20Poly1305,
    operation: Operation,
    on_progress: impl Fn(usize, usize) + Send + 'static + Clone,
) -> Result<(), EncError> {
    let files = get_files(path)?;

    let nonce = Arc::new(Mutex::new(nonce));
    let cipher = Arc::new(Mutex::new(cipher));
    let progress = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = files
        .clone()
        .into_iter()
        .map(|file| {
            let progress = Arc::clone(&progress);
            let nonce = Arc::clone(&nonce);
            let cipher = Arc::clone(&cipher);
            let on_progress = on_progress.clone();
            let value = files.clone();
            thread::spawn(move || {
                let nonce = nonce.lock().unwrap();
                let cipher = cipher.lock().unwrap();
                let processed = progress.fetch_add(1, Ordering::SeqCst) + 1;
                on_progress(processed, value.len());
                process_file(file, *nonce, cipher.clone(), operation)
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap()?; // Handle the result or error
    }
    Ok(())
}

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
    let (nonce, cipher) = generate_key();

    let mut originals = Vec::new();
    for i in 0..10 {
        let name = &format!("./{}/{}", folder, i).to_owned();
        generate_dummy_file(name, 15).unwrap();
        originals.push(std::fs::read(name).unwrap());
    }

    process_folder(
        format!("./{}", folder).into(),
        nonce,
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
        nonce,
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

    let (nonce, cipher) = new_key("test").unwrap();
    process_folder(
        format!("./{}", folder).into(),
        nonce,
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

    let (nonce, cipher) = new_key("test2").unwrap();
    assert_eq!(
        process_folder(
            format!("./{}", folder).into(),
            nonce,
            cipher,
            Operation::Decrypt,
            |_, _| {}
        )
        .unwrap_err(),
        EncError::Decode
    );

    let (nonce, cipher) = new_key("test").unwrap();
    process_folder(
        format!("./{}", folder).into(),
        nonce,
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
