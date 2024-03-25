use std::time::Instant;

use num_bigint::BigUint;
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};
use util::from_biguint_dig_to_biguint;

mod util;

// Params for Dioidon.
// TODO: Add hash function as a param.
pub struct Params {
    m: usize,
    l: usize,
    time_complexity: usize,
    hash_bytes_size: usize,
}

pub struct PublicKey {
    rsa_n: BigUint,
}

pub struct PrivateKey {
    rsa_p: BigUint,
    rsa_q: BigUint,
    rsa_n: BigUint,
    rsa_phi_n: BigUint,
}

pub fn generate_2048_bit_keys() -> (PrivateKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_phi_n = from_biguint_dig_to_biguint(&(&key.primes()[0] * &key.primes()[1]));
    (
        PrivateKey {
            rsa_p: from_biguint_dig_to_biguint(&key.primes()[0]),
            rsa_q: from_biguint_dig_to_biguint(&key.primes()[1]),
            rsa_n: from_biguint_dig_to_biguint(&key.n()),
            rsa_phi_n: rsa_phi_n,
        },
        PublicKey {
            rsa_n: from_biguint_dig_to_biguint(&key.n()),
        },
    )
}

pub fn hard() {}

fn diodon_non_privileged(
    x_cipher_block: usize,
    rsa_n: BigUint,
    m: usize,
    l: usize,
    time_complexity: usize,
    hash_bytes_size: usize,
) -> Vec<u8> {
    let x = BigUint::from(x_cipher_block);
    let mut v: Vec<BigUint> = Vec::<BigUint>::with_capacity(m);
    v.push(x);
    let start: Instant = Instant::now();
    for i in 1..m {
        v.push(util::squaring(&v[i - 1], time_complexity, &rsa_n));
    }
    println!("Time elapsed in vector_pushing() is: {:?}", start.elapsed());
    let start: Instant = Instant::now();

    let mut s_bytes = v.last().unwrap().to_bytes_be();

    let mut j: usize;
    for _i in 0..l {
        j = (BigUint::from_bytes_be(&s_bytes) % m).try_into().unwrap();
        j %= m;
        s_bytes.extend(v[j].to_bytes_be().iter());
        s_bytes = blake3::hash(&s_bytes).as_bytes().to_vec();
    }
    println!("Time elapsed in L() is: {:?}", start.elapsed());
    println!("{:?}", s_bytes);
    s_bytes[s_bytes.len() - hash_bytes_size..].to_vec()
}

fn diodon_privileged(
    x_cipher_block: usize,
    rsa_p: &BigUint,
    rsa_q: &BigUint,
    m: usize,
    l: usize,
    time_complexity: usize,
    hash_bytes_size: usize,
) -> Vec<u8> {
    let x: BigUint = x_cipher_block.into();
    let exponent = BigUint::from((m - 1) * time_complexity);
    let phi_n = (rsa_p - 1usize) * (rsa_q - 1usize);
    let n = rsa_p * rsa_q;
    let two = BigUint::from(2u32);
    let e = two.modpow(&exponent, &phi_n);
    let mut s_bytes = x.modpow(&e, &n).to_bytes_be();

    let start_l = Instant::now();
    let mut j: BigUint;
    let mut x_ej: BigUint;
    let mut e_j: BigUint;
    for _i in 0..l {
        j = BigUint::from_bytes_be(&s_bytes) % m;
        e_j = two
            .modpow(&j, &phi_n)
            .modpow(&time_complexity.into(), &phi_n);
        x_ej = x.modpow(&e_j, &n);
        s_bytes.extend(x_ej.to_bytes_be().iter());
        s_bytes = blake3::hash(&s_bytes).as_bytes().to_vec();
    }
    let duration = start_l.elapsed();
    println!("Time elapsed in privileged L() is: {:?}", duration);
    s_bytes[s_bytes.len() - hash_bytes_size..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diodon_hard_equals_privileged() {
        let q = BigUint::parse_bytes(b"12772322319733548247851901381850054224408980869676616358291561606873489416423155106454795516367791954119113161475136097310823566024399906461641393526506223", 10).unwrap();
        let p = BigUint::parse_bytes(b"13270159569298364102590828989123999927823242049974571921817075346300096102090311023718167382683031794589299932545623449542461777499628836970633616840367291", 10).unwrap();
        let rsa_n = &p * &q;
        let cipher: usize = 21;
        let m = 4000;
        let l = 4000;
        let u_bytes: usize = 16; //128 bits
        let time_complexity = 2048;
        let hashed_hard = diodon_non_privileged(cipher, rsa_n, m, l, time_complexity, u_bytes);
        let hashed_easy = diodon_privileged(cipher, &p, &q, m, l, time_complexity, u_bytes);
        println!(
            "hashed_hard={:?}, hashed_easy={:?}",
            hashed_hard, hashed_easy
        );
        assert_eq!(hashed_hard, hashed_easy);
    }
}
