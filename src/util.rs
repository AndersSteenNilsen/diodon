use num_bigint::BigUint;
use num_traits::One;
use rsa::BigUint as RsaBigUint;

/// Calculates b^(2^e) mod n
pub fn squaring(b: &BigUint, e: usize, n: &BigUint) -> BigUint {
    if e == 1 {
        return b * b % n;
    }
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

pub fn memory_blocks(
    start_value: &BigUint,
    memory_factor: usize,
    time_complexity: usize,
    modulus: &BigUint,
) -> Vec<num_bigint::BigUint> {
    let mut v: Vec<BigUint> = Vec::<BigUint>::with_capacity(memory_factor);
    let mut v_minus_1 = start_value.clone();
    v.push(v_minus_1.clone());
    for _i in 1..memory_factor {
        v_minus_1 = squaring(&v_minus_1, time_complexity, modulus);
        v.push(v_minus_1.clone());
        //v.push(squaring(&v[i - 1], time_complexity, modulus));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    #[bench]
    fn bench_large_square_two(bencher: &mut Bencher) {
        let base = BigUint::parse_bytes(b"1024", 10).unwrap();
        let e = 256usize;
        let q = BigUint::parse_bytes(b"156968538006454153552154918080725604889881249793955878307143380021187327061208436911326291489110631759094141457413830907419424449436820339912357318330772975266767639408357800395570329480229784588927678308046854933619619353739869481851305550105159797781519661688972486987059268302270270193066850179922150396937", 10).unwrap();
        let p = BigUint::parse_bytes(b"138154375592216506317406833347480794151135359156985136226058739441317232969359215666883048156303905347167585362049791808140291742161041436935911667281520624494327845377621238269655349853869338664638587537443448410326271340862757680139090487799781391799061369299343370912316229801139344805020703321280063177759", 10).unwrap();
        let n = p * q;
        bencher.iter(|| squaring(&base, e, &n));
    }

    #[bench]
    fn bench_e_1_square_two(bencher: &mut Bencher) {
        let base = BigUint::parse_bytes(b"1024", 10).unwrap();
        let e = 1usize;
        let q = BigUint::parse_bytes(b"156968538006454153552154918080725604889881249793955878307143380021187327061208436911326291489110631759094141457413830907419424449436820339912357318330772975266767639408357800395570329480229784588927678308046854933619619353739869481851305550105159797781519661688972486987059268302270270193066850179922150396937", 10).unwrap();
        let p = BigUint::parse_bytes(b"138154375592216506317406833347480794151135359156985136226058739441317232969359215666883048156303905347167585362049791808140291742161041436935911667281520624494327845377621238269655349853869338664638587537443448410326271340862757680139090487799781391799061369299343370912316229801139344805020703321280063177759", 10).unwrap();
        let n = p * q;
        bencher.iter(|| squaring(&base, e, &n));
    }

    #[bench]
    fn bench_vector_pushing(bencher: &mut Bencher) {
        let base = BigUint::parse_bytes(b"1024", 10).unwrap();
        let e = 1usize;
        let q = BigUint::parse_bytes(b"156968538006454153552154918080725604889881249793955878307143380021187327061208436911326291489110631759094141457413830907419424449436820339912357318330772975266767639408357800395570329480229784588927678308046854933619619353739869481851305550105159797781519661688972486987059268302270270193066850179922150396937", 10).unwrap();
        let p = BigUint::parse_bytes(b"138154375592216506317406833347480794151135359156985136226058739441317232969359215666883048156303905347167585362049791808140291742161041436935911667281520624494327845377621238269655349853869338664638587537443448410326271340862757680139090487799781391799061369299343370912316229801139344805020703321280063177759", 10).unwrap();
        let n = p * q;
        bencher.iter(|| memory_blocks(&base, 4_000usize, e, &n));
    }
}
pub fn from_biguint_dig_to_biguint(rsa_biguint: &RsaBigUint) -> BigUint {
    BigUint::from_bytes_le(&rsa_biguint.to_bytes_le())
}

// Calculate q^-1 mod p
fn inverse(p: &BigUint, q: &BigUint) -> BigUint {
    p.modpow(&(q - 2usize), q)
}
#[test]
fn test_inverse() {
    let p = BigUint::from_u8(31u8).unwrap();
    let q = BigUint::from_u8(37u8).unwrap();
    let expected = BigUint::from_u8(6u8).unwrap();
    assert_eq!(inverse(&p, &q), expected);
}

// Calculate c^d mod p * q
pub fn crt_pow_mod(c: &BigUint, d: &BigUint, p: &BigUint, q: &BigUint) -> BigUint {
    let d_p = d % (p - 1usize);
    let d_q = d % (q - 1usize);
    let q_inv = inverse(q, p);

    let m_1 = c.modpow(&d_p, p);
    let m_2 = c.modpow(&d_q, q);
    let m_diff = if m_1 >= m_2 {
        m_1 - &m_2
    } else {
        (2usize * p + &m_1) - &m_2
    };
    let h = q_inv * m_diff % p;
    (m_2 + h * q) % (p * q)
}
#[test]
fn test_crt_pow_mod() {
    let c = BigUint::from_u8(5u8).unwrap();
    let d = BigUint::from_u8(200u8).unwrap();

    let p = BigUint::from_u8(37u8).unwrap();
    let q = BigUint::from_u8(31u8).unwrap();

    let expected = BigUint::from_u16(1048u16).unwrap();

    assert_eq!(crt_pow_mod(&c, &d, &p, &q), expected);
}
