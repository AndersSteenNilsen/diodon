#![feature(test)]
extern crate test;

use std::time::Instant;

use num_bigint::BigUint;
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};
use util::from_biguint_dig_to_biguint;

mod util;

pub fn conservative_params() -> Params {
    Params {
        m: 4_000usize,
        l: 4_000usize,
        time_complexity: 2048usize,
        key_bit_size: 2048usize,
        hash_bytes_size: 16usize,
    }
}

pub fn fast_params() -> Params {
    Params {
        m: 8_000_000usize,
        l: 20_000usize,
        time_complexity: 1usize,
        key_bit_size: 1024,
        hash_bytes_size: 16usize,
    }
}

// Params for Dioidon.
// TODO: Add hash function as a param.
pub struct Params {
    m: usize,
    l: usize,
    time_complexity: usize,
    pub key_bit_size: usize,
    hash_bytes_size: usize,
}

pub struct PublicKey {
    rsa_n: BigUint,
}

#[derive(Debug)]
pub struct PrivateKey {
    rsa_p: BigUint,
    rsa_q: BigUint,
}

pub fn generate_keys(bit_size: usize) -> (PrivateKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let key = RsaPrivateKey::new(&mut rng, bit_size).unwrap();
    (
        PrivateKey {
            rsa_p: from_biguint_dig_to_biguint(&key.primes()[0]),
            rsa_q: from_biguint_dig_to_biguint(&key.primes()[1]),
        },
        PublicKey {
            rsa_n: from_biguint_dig_to_biguint(key.n()),
        },
    )
}

pub fn privileged(cipher: &[u8], private_key: PrivateKey, params: &Params) -> Vec<u8> {
    diodon_privileged(
        cipher,
        &private_key.rsa_p,
        &private_key.rsa_q,
        params.m,
        params.l,
        params.time_complexity,
        params.hash_bytes_size,
    )
}

pub fn non_priviledged(cipher: &[u8], public_key: PublicKey, params: &Params) -> Vec<u8> {
    diodon_non_privileged(
        cipher,
        &public_key.rsa_n,
        params.m,
        params.l,
        params.time_complexity,
        params.hash_bytes_size,
    )
}

fn diodon_non_privileged(
    cipher: &[u8],
    rsa_n: &BigUint,
    m: usize,
    l: usize,
    time_complexity: usize,
    hash_bytes_size: usize,
) -> Vec<u8> {
    let x = BigUint::from_bytes_le(cipher);
    let start: Instant = Instant::now();
    let v = util::memory_blocks(&x, m, time_complexity, rsa_n);

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
    s_bytes[s_bytes.len() - hash_bytes_size..].to_vec()
}

fn diodon_privileged(
    cipher: &[u8],
    rsa_p: &BigUint,
    rsa_q: &BigUint,
    m: usize,
    l: usize,
    time_complexity: usize,
    hash_bytes_size: usize,
) -> Vec<u8> {
    let x: BigUint = BigUint::from_bytes_le(cipher); // x_cipher_block.into();
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
        let q = BigUint::parse_bytes(b"156968538006454153552154918080725604889881249793955878307143380021187327061208436911326291489110631759094141457413830907419424449436820339912357318330772975266767639408357800395570329480229784588927678308046854933619619353739869481851305550105159797781519661688972486987059268302270270193066850179922150396937", 10).unwrap();
        let p = BigUint::parse_bytes(b"138154375592216506317406833347480794151135359156985136226058739441317232969359215666883048156303905347167585362049791808140291742161041436935911667281520624494327845377621238269655349853869338664638587537443448410326271340862757680139090487799781391799061369299343370912316229801139344805020703321280063177759", 10).unwrap();
        let rsa_n = &p * &q;
        let cipher: &[u8] = b"Hello Diodon";
        let m = 4_000usize;
        let l = 4_000usize;
        let u_bytes: usize = 16; //128 bits
        let time_complexity = 2048;
        let hashed_easy = diodon_privileged(cipher, &p, &q, m, l, time_complexity, u_bytes);
        let hashed_hard = diodon_non_privileged(cipher, &rsa_n, m, l, time_complexity, u_bytes);
        println!(
            "hashed_hard={:?}, hashed_easy={:?}",
            hashed_hard, hashed_easy
        );
        assert_eq!(hashed_hard, hashed_easy);
    }
}
