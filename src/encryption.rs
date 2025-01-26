use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::Rng;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

#[derive(Copy, Clone, Debug)]
pub enum EncError {
    Read,
    Write,
    Encode,
    Decode,
}

#[derive(Copy, Clone, Debug)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

fn get_files(folder: String) -> Result<Vec<PathBuf>, EncError> {
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

pub fn generate_key() -> (Nonce, ChaCha20Poly1305) {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    (nonce, cipher)
}

pub fn process_folder(
    path: String,
    nonce: Nonce,
    cipher: ChaCha20Poly1305,
    operation: Operation,
) -> Result<(), EncError> {
    let files = get_files(path)?;
    for file in files {
        process_file(file, nonce, cipher.clone(), operation)?
    }
    Ok(())
}

#[cfg(test)]
fn generate_dummy_file(file_path: &str, size: usize) -> Result<(), EncError> {
    fs::create_dir_all("./dummy").map_err(|_| EncError::Write)?;
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..size).map(|_| rng.r#gen()).collect();

    let mut file = File::create(file_path).map_err(|_| EncError::Write)?;
    file.write_all(&data).map_err(|_| EncError::Write)?;
    Ok(())
}

#[test]
fn test_encryption_decryption() {
    let (nonce, cipher) = generate_key();

    let mut originals = Vec::new();
    for i in 0..10 {
        let name = &format!("./dummy/{}", i).to_owned();
        generate_dummy_file(name, 15).unwrap();
        originals.push(std::fs::read(name).unwrap());
    }

    process_folder(
        "./dummy/".to_string(),
        nonce,
        cipher.clone(),
        Operation::Encrypt,
    )
    .unwrap();

    let mut encrypteds = Vec::new();
    for i in 0..10 {
        let name = &format!("./dummy/{}", i).to_owned();
        encrypteds.push(std::fs::read(name).unwrap());
    }
    assert_ne!(originals, encrypteds);

    process_folder("./dummy/".to_string(), nonce, cipher, Operation::Decrypt).unwrap();

    let mut decrypteds = Vec::new();
    for i in 0..10 {
        let name = &format!("./dummy/{}", i).to_owned();
        decrypteds.push(std::fs::read(name).unwrap());
    }
    assert_eq!(originals, decrypteds);

    fs::remove_dir_all("./dummy/").unwrap();
}
