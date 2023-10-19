use std::{fmt::Debug, ops::{IndexMut, Index}};

use ark_ff::PrimeField;

pub trait Permutation<F: Clone + Debug + Default>: Clone + Debug + Default + Index<usize, Output = F> + IndexMut<usize, Output = F> {
    const RATE: usize;
    const WIDTH: usize;

    fn new(items: &[F]) -> Self;
    fn permute(&mut self);
}

pub trait Hasher<F: PrimeField> {
    type Hash: Clone + PartialEq + Debug + Copy;
    type Permutation: Permutation<F>;

    fn hash_pad(data:&[F]) -> Self::Hash {
        let mut padded_data = data.to_vec();
        padded_data.push(F::ONE);
        while (padded_data.len()+1) % Self::Permutation::WIDTH != 0 {
            padded_data.push(F::ZERO);
        }
        padded_data.push(F::ONE);
        Self::hash_no_pad(&padded_data)
    }

    fn hash_no_pad(data: &[F]) -> Self::Hash;

    // fn hash_out_field(data: F) -> Self::Hash;
    fn hash_two_to_one(data1:Self::Hash, data2: Self::Hash) -> Self::Hash;

    fn hash_as_field(hash: Self::Hash) -> F;
}
