use std::{marker::PhantomData, fmt::Debug};

use ark_ff::PrimeField;
use rs_merkle::{algorithms::Sha256, Hasher};


pub trait Hasher_<F: PrimeField> {
    type Hash: Clone + PartialEq + Debug + Copy;

    fn hash(data:F) -> Self::Hash;

    // fn hash_out_field(data: F) -> Self::Hash;
    fn hash_two_to_one(data1:Self::Hash, data2: Self::Hash) -> Self::Hash;

    fn hash_as_field(hash: Self::Hash) -> F;
}

pub struct Sha256_<F: PrimeField> {
    _f: PhantomData<F>,
}

impl<F: PrimeField> Hasher_<F> for Sha256_<F> {
    type Hash = F;

    fn hash(data: F) -> Self::Hash {
        let d: Vec<u8> = data.to_string().into();
        F::from_le_bytes_mod_order(&Sha256::hash(&d))
    }

    fn hash_two_to_one(data1: Self::Hash, data2: Self::Hash) -> Self::Hash {
        let mut d: Vec<u8> = data1.to_string().into();
        let mut d1: Vec<u8> = data2.to_string().into();
        d.append(&mut d1);
        let h = Sha256::hash(&d);
        F::from_le_bytes_mod_order(&h)
    }

    fn hash_as_field(hash: Self::Hash) -> F {
        hash
    }
}