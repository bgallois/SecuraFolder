/// A module for file encryption and decryption using the ChaCha20-Poly1305 cipher.
///
/// This module provides functionality for processing files in a directory, including:
/// - Encrypting or decrypting files using a password-based key or a randomly generated key.
/// - Checking whether a directory's files can be successfully decrypted.
/// - Generating new encryption keys based on a password or random generation.
///
/// # Key Features
/// - File Processing: It can encrypt and decrypt files in a given folder, updating the files with the appropriate cipher data.
/// - Parallel Processing: It uses a thread pool to handle file processing concurrently, speeding up the operations on large numbers of files.
/// - Password-Based Encryption: Supports key generation from a password using the Argon2 algorithm.
///
use argon2::PasswordHasher;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::Rng;
use sha2::{Digest, Sha256};
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

/// Enumeration representing various types of errors that can occur during file encryption or decryption.
///
/// # Variants
/// - `Read`: An error occurred while reading a file.
/// - `Write`: An error occurred while writing to a file.
/// - `Encode`: An error occurred while encoding data (e.g., encryption failure).
/// - `Decode`: An error occurred while decoding data (e.g., decryption failure).
/// - `Key`: An error occurred while handling or generating a cryptographic key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncError {
    Read,
    Write,
    Encode,
    Decode,
    Key,
}

/// Enumeration representing the two possible operations for file processing: encryption and decryption.
///
/// # Variants
/// - `Encrypt`: The operation will encrypt the file.
/// - `Decrypt`: The operation will decrypt the file.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Operation {
    Encrypt,
    Decrypt,
}

/// Retrieves all file paths from a given folder.
///
/// This function recursively walks through a given folder and collects all file paths,
/// returning them in a `Vec<PathBuf>`.
///
/// # Arguments
/// * `folder` - A `PathBuf` representing the folder to search for files.
///
/// # Returns
/// * `Result<Vec<PathBuf>, EncError>` - A `Vec<PathBuf>` containing the paths of all found files if successful,
///   otherwise an `EncError::Read` if reading the directory fails.
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

/// Processes a file (either encrypts or decrypts it).
///
/// This function reads a file, encrypts or decrypts it based on the `operation` parameter,
/// and writes the resulting ciphertext or plaintext back to the file. If encryption is performed,
/// a nonce is prepended to the file content. If decryption is performed, it expects the nonce
/// to be present at the beginning of the file and removes it before decrypting.
///
/// # Arguments
/// * `file_path` - A `PathBuf` representing the file to process.
/// * `cipher` - A `ChaCha20Poly1305` cipher to use for the encryption or decryption.
/// * `operation` - The operation to perform (`Encrypt` or `Decrypt`).
///
/// # Returns
/// * `Result<(), EncError>` - `Ok(())` if the operation completes successfully, or an error variant if a failure occurs during reading, writing, encoding, or decoding.
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

// Checks if any file in the given directory is decodable.
///
/// This function retrieves all files in a given folder and attempts to decrypt a random file
/// from the folder to check if the files are decodable using the provided cipher. It is useful
/// for determining if a folder of files can be decrypted with the current key.
///
/// # Arguments
/// * `path` - A `PathBuf` representing the folder containing files to check.
/// * `cipher` - A `ChaCha20Poly1305` cipher used to attempt decryption of the files.
///
/// # Returns
/// * `bool` - `true` if at least one file can be decrypted successfully, `false` otherwise.
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

/// Generates a random key for ChaCha20-Poly1305 encryption.
///
/// This function generates a random 256-bit key using the `OsRng` random number generator
/// and returns a `ChaCha20Poly1305` cipher initialized with the generated key. It is useful
/// for creating a new encryption key without requiring a password.
///
/// # Returns
/// * `ChaCha20Poly1305` - A ChaCha20-Poly1305 cipher initialized with the generated random key.
pub fn generate_key() -> ChaCha20Poly1305 {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    ChaCha20Poly1305::new(&key)
}

/// Generates a key for ChaCha20-Poly1305 encryption from a password.
///
/// This function uses the Argon2 password hashing algorithm to derive a key from the provided password.
/// The password is hashed with a fixed salt, and the resulting key is used to initialize
/// a `ChaCha20Poly1305` cipher for encryption or decryption operations.
///
/// # Arguments
/// * `password` - A `&str` containing the password to derive the key from.
///
/// # Returns
/// * `Result<ChaCha20Poly1305, EncError>` - A `ChaCha20Poly1305` cipher initialized with the derived key if successful,
///   or an `EncError::Key` if the key generation fails.
pub fn new_key(password: &str) -> Result<ChaCha20Poly1305, EncError> {
    let salt = generate_salt(password);
    let salt = argon2::password_hash::Salt::from_b64(&salt).map_err(|_| EncError::Key)?;
    let argon2 = argon2::Argon2::default();
    let key = argon2
        .hash_password(password.as_bytes(), salt)
        .map_err(|_| EncError::Key)?;
    let cipher = ChaCha20Poly1305::new_from_slice(key.hash.ok_or(EncError::Key)?.as_bytes())
        .map_err(|_| EncError::Key)?;
    Ok(cipher)
}

/// Generates a salt derived from the provided password.
///
/// This function uses the SHA-256 hashing algorithm to generate a salt for cryptographic use.
/// It combines the provided password with a fixed string ("secura_folder") to ensure a unique,
/// deterministic salt for the given password. The resulting salt is returned as a hexadecimal string.
///
/// # Arguments
/// * `password` - A string slice (`&str`) representing the user's password, which is used to generate the salt.
///
/// # Returns
/// * `String` - A hexadecimal representation of the generated salt, which can be used in cryptographic operations
///   like key derivation.
fn generate_salt(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"secura_folder");
    let salt = hasher.finalize();
    hex::encode(salt)
}

/// Processes all files in a folder (either encrypts or decrypts them).
///
/// This function retrieves all files from a specified folder and processes them concurrently using
/// a thread pool. Each file is either encrypted or decrypted based on the provided operation. The
/// function also tracks and reports the progress of the operation using the `on_progress` callback.
/// This function choose to panic if a mutex is poisoned as there is not recovery possible at this stage.
/// TODO: keep a list of encoded/decoded files and backtrack if poisonous Mutex.
///
/// # Arguments
/// * `path` - A `PathBuf` representing the folder containing files to process.
/// * `cipher` - A `ChaCha20Poly1305` cipher to use for the encryption or decryption of the files.
/// * `operation` - The operation to perform (`Encrypt` or `Decrypt`).
/// * `on_progress` - A callback function that is called with the progress of the operation (processed files, total files).
///
/// # Returns
/// * `Result<(), EncError>` - `Ok(())` if the operation completes successfully, or an error variant if a failure occurs during any part of the file processing.
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
