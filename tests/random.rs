//! CS410P - Homework #2: Toy RSA
//! Zach Roth 2023
//!
//! toy_rsa unit tests
//!
//! Resources:
//! https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
//! https://docs.rs/primal/latest/primal/

use toy_rsa::*;
use toy_rsa_lib::*;

pub const EXP: u64 = 65_537;

#[cfg(test)]
mod tests {
    use super::*;
    use primal::is_prime;
    use rand::*;

    #[test]
    fn test_genkey() {
        let (p, q) = genkey();
        assert!(is_prime(p as u64));
        assert!(is_prime(q as u64));
        assert!(p >= (1 << 31) && p <= u32::MAX);
        assert!(q >= (1 << 31) && q <= u32::MAX);
    }

    #[test]
    fn test_encrypt() {
        let mut rng = rand::thread_rng();
        let p: u32 = rsa_prime();
        let q: u32 = rsa_prime();
        let n = p as u64 * q as u64;
        let plaintext: u32 = rng.gen();
        let ciphertext: u64 = encrypt(n, plaintext);
        assert_ne!(ciphertext, u64::from(plaintext));
    }

    #[test]
    fn test_decrypt() {
        let mut rng = rand::thread_rng();
        let msg: u32 = rng.gen();
        let (p, q) = genkey();
        let n = u64::from(p) * u64::from(q);
        let ciphertext = encrypt(n, msg);
        let decrypted_text = decrypt((p, q), ciphertext);
        assert_eq!(msg, decrypted_text);
    }
}
