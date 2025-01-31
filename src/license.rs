use license_key::*;

struct Hasher;
impl KeyHasher for Hasher {
    fn hash(&self, seed: u64, a: u64, b: u64, c: u64) -> u8 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.to_le_bytes());
        hasher.update(&a.to_le_bytes());
        hasher.update(&b.to_le_bytes());
        hasher.update(&c.to_le_bytes());
        let result = hasher.finalize();
        result.as_bytes()[0]
    }
}
impl Default for Hasher {
    fn default() -> Self {
        Hasher
    }
}

trait LicenseManager<T> {
    fn new(iteration: u8) -> Self;
    fn block(&mut self, key: &str);
    fn verify(&self, key: &str) -> Status;
    fn generate(&self, mail: &str) -> String;
}

struct Manager<T: KeyHasher> {
    verifier: Verifier<T>,
    generator: Generator<T>,
}
impl<T: KeyHasher + std::default::Default> LicenseManager<T> for Manager<T> {
    fn new(iteration: u8) -> Self {
        let verifier: Verifier<T> = Verifier::new(T::default(), vec![
            // Change this to discontinu forged keys
            ByteCheck::new(iteration, (114, 83, 170)),
        ]);
        let generator = Generator::new(T::default(), vec![
            (114, 83, 170),
            (60, 208, 27),
            (69, 14, 202),
            (61, 232, 54),
        ]);
        Self {
            verifier,
            generator,
        }
    }

    fn block(&mut self, mail: &str) {
        let mut hash = 0u64;
        for byte in mail.bytes() {
            hash = hash.wrapping_mul(1099511628211).wrapping_add(byte as u64);
        }
        self.verifier.block(hash);
    }

    fn verify(&self, key: &str) -> Status {
        let key = LicenseKey::parse::<HexFormat>(&key);
        self.verifier.verify(&key)
    }

    fn generate(&self, mail: &str) -> String {
        let mut hash = 0u64;
        for byte in mail.bytes() {
            hash = hash.wrapping_mul(1099511628211).wrapping_add(byte as u64);
        }
        let key = self.generator.generate(hash);
        key.serialize::<HexFormat>()
    }
}

#[test]
fn test_generation_verification() {
    let manager = Manager::<Hasher>::new(0);
    let key = manager.generate("test@test.fr");
    assert_eq!(manager.verify(&key), Status::Valid);
}

#[test]
fn test_invalid() {
    let manager = Manager::<Hasher>::new(0);
    let key = manager.generate("test@test.fr");
    assert_eq!(
        manager.verify("14549b21366db0aa219d1302d0b7"),
        Status::Invalid
    );
}

#[test]
fn test_blocked() {
    let mut manager = Manager::<Hasher>::new(0);
    let key = manager.generate("test@test.fr");
    manager.block("test@test.fr");
    assert_eq!(manager.verify(&key), Status::Blocked);
}

#[test]
fn test_forget() {
    let manager = Manager::<Hasher>::new(0);
    let key = manager.generate("test@test.fr");
    let manager = Manager::<Hasher>::new(1);
    assert_eq!(manager.verify(&key), Status::Forged);
}
