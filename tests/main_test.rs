use diodon::Params;

#[test]
fn fast_diodon_hash() {
    let fast_params: Params = diodon::fast_params();
    let cipher: &[u8; 12] = b"Hello Diodon";
    let (private_key, public_key) = diodon::generate_keys(fast_params.key_bit_size);
    let hash_priviledgeged: Vec<u8> = diodon::privileged(cipher, private_key, &fast_params);
    let hash_non_privileged: Vec<u8> = diodon::non_priviledged(cipher, public_key, &fast_params);
    assert_eq!(hash_priviledgeged, hash_non_privileged);
    println!("{:?}\n{:?}", hash_non_privileged, hash_priviledgeged);
}

#[test]
fn conservative_diodon_hash() {
    let conservative_params: Params = diodon::conservative_params();
    let cipher: &[u8; 12] = b"Hello Diodon";
    let (private_key, public_key) = diodon::generate_keys(conservative_params.key_bit_size);
    println!("{:?}", private_key);
    let hash_priviledgeged: Vec<u8> = diodon::privileged(cipher, private_key, &conservative_params);
    let hash_non_privileged: Vec<u8> =
        diodon::non_priviledged(cipher, public_key, &conservative_params);
    assert_eq!(hash_priviledgeged, hash_non_privileged);
    println!("{:?}\n{:?}", hash_non_privileged, hash_priviledgeged);
}
