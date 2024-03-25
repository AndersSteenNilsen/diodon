use num_bigint::BigUint;
use num_traits::One;
use rsa::BigUint as RsaBigUint;

/// Calculates b^(2^e) mod n
pub fn squaring(b: &BigUint, e: usize, n: &BigUint) -> BigUint {
    b.modpow(&(BigUint::one() << e), n)
}

#[test]
fn test_2pow2pow2() {
    let b = BigUint::parse_bytes(b"2", 10).unwrap();
    let e = 2usize;
    let n = BigUint::parse_bytes(b"1_000", 10).unwrap();
    let result = squaring(&b, e, &n);
    assert_eq!(result, 16usize.into());
}

#[test]
fn test_2pow2pow3() {
    let b = BigUint::parse_bytes(b"2", 10).unwrap();
    let e = 3usize;
    let n = BigUint::parse_bytes(b"1_000", 10).unwrap();
    let result = squaring(&b, e, &n);
    assert_eq!(result, 256usize.into());
}

#[test]
fn test_2pow2pow4() {
    let b = BigUint::parse_bytes(b"2", 10).unwrap();
    let e = 4usize;
    let n = BigUint::parse_bytes(b"1_000_000", 10).unwrap();
    let result = squaring(&b, e, &n);
    assert_eq!(result, 65536usize.into());
}

#[test]
fn test_2pow2pow10() {
    let b = BigUint::parse_bytes(b"2", 10).unwrap();
    let e = 10usize;
    let n = BigUint::parse_bytes(b"1_000_000", 10).unwrap();
    let result = squaring(&b, e, &n);
    assert_eq!(result, 137216usize.into());
}

#[test]
fn test_1024pow2pow1024() {
    let b = BigUint::parse_bytes(b"1024", 10).unwrap();
    let e = 1024usize;
    let n = BigUint::parse_bytes(b"1_000_000", 10).unwrap();
    let result = squaring(&b, e, &n);
    assert_eq!(result, 662976usize.into());
}

pub fn from_biguint_dig_to_biguint(rsa_biguint: &RsaBigUint) -> BigUint {
    BigUint::from_bytes_le(&rsa_biguint.to_bytes_le())
}
