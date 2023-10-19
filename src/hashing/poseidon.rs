use std::{ops::{IndexMut, Index}, fmt::Debug};

use ark_ff::PrimeField;

use super::hasher::{Permutation, Hasher};

const SPONGE_RATE: usize = 8;
const SPONGE_CAPACITY: usize = 4;
const SPONGE_WIDTH: usize = SPONGE_RATE + SPONGE_CAPACITY;
const NUM_ELEMENTS_HASH_OUTPUT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashOutput<F: PrimeField> {
    pub outputs: [F; NUM_ELEMENTS_HASH_OUTPUT],
}

#[derive(Clone, Debug, Default)]
pub struct PoseidonPermutation<F> {
    state: [F; SPONGE_WIDTH],
}

impl<F> Index<usize> for PoseidonPermutation<F> {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.state[index]
    }
}

impl<F> IndexMut<usize> for PoseidonPermutation<F> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.state[index]
    }
}

impl<F: Clone + Default + Debug> Permutation<F> for PoseidonPermutation<F> {
    const RATE: usize = SPONGE_RATE;

    const WIDTH: usize = SPONGE_WIDTH;

    fn new(items: &[F]) -> Self {
        todo!()
    }

    fn permute(&mut self) {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct PoseidonHash;
impl<F: PrimeField> Hasher<F> for PoseidonHash {
    type Hash = HashOutput<F>;

    type Permutation = PoseidonPermutation<F>;

    fn hash_no_pad(data: &[F]) -> Self::Hash {
        todo!()
    }

    fn hash_two_to_one(data1:Self::Hash, data2: Self::Hash) -> Self::Hash {
        todo!()
    }

    fn hash_as_field(hash: Self::Hash) -> F {
        todo!()
    }
}
