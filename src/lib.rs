//! CS410P - Homework #2: Toy RSA
//! Zach Roth 2023
//! Homework #2
//! Spring 2023

//! https://pdx-cs-rust.github.io/toy-rsa-lib/toy_rsa_lib/index.html
use std::convert::TryFrom;
use toy_rsa_lib::*;

pub const EXP: u64 = 65_537;

// Generate a pair of primes in the range `2**31..2**32`
// suitable for RSA encryption with exponent.
pub fn genkey() -> (u32, u32) {
    loop {
        let p: u32 = rsa_prime();
        let q: u32 = rsa_prime();
        // Convert to 64-bit
        let p_64 = u64::from(p);
        let q_64 = u64::from(q);
        let lcm: u64 = lcm(p_64 - 1, q_64 - 1);

        if EXP < lcm && gcd(EXP, lcm) == 1 {
            let prime1: u32 = match u32::try_from(p_64) {
                Ok(val) => val,
                Err(_) => panic!("Too big for unsigned 32-bit!!!"),
            };
            let prime2: u32 = match u32::try_from(q_64) {
                Ok(val) => val,
                Err(_) => panic!("Too big for unsigned 32-bit!!!"),
            };

            return (prime1, prime2);
        }
    }
}

// Encrypt the plaintext `msg` using the RSA public `key`
// and return the ciphertext.
pub fn encrypt(key: u64, msg: u32) -> u64 {
    let msg_64 = u64::from(msg);

    let ciphertext: u64 = modexp(msg_64, EXP, key);
    ciphertext
}

// Decrypt the ciphertext `msg` using the RSA private `key`
// and return the resulting plaintext.
pub fn decrypt(key: (u32, u32), msg: u64) -> u32 {
    let p = u64::from(key.0);
    let q = u64::from(key.1);

    let lcm: u64 = lcm(p - 1, q - 1);
    let d = modinverse(EXP, lcm);

    let n: u64 = p * q;

    let plaintext: u64 = modexp(msg, d, n);
    plaintext

    match u32::try_from(plaintext) {
        Ok(val) => val,
        Err(_) => panic!("Too big for unsigned 32-bit!!!"),
    }
}
