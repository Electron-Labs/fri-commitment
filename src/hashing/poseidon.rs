use std::{ops::{IndexMut, Index}, fmt::Debug};

use super::hasher::Permutation;

const SPONGE_RATE: usize = 8;
const SPONGE_CAPACITY: usize = 4;
const SPONGE_WIDTH: usize = SPONGE_RATE + SPONGE_CAPACITY;

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
