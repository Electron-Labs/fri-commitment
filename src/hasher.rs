use std::marker::PhantomData;

use ark_ff::PrimeField;

use rs_merkle::{algorithms::Sha256, Hasher};

pub trait Hasher_<F: PrimeField> {
    type Hash;

    fn hash(data:F) -> [u8; 32];
}

pub struct Sha256_<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Hasher_<F> for Sha256_<F> {
    type Hash = [u8; 32];

    fn hash(data: F) -> [u8; 32] {
        let data: Vec<u8> = data.to_string().into();
        Sha256::hash(&data)
    }
}