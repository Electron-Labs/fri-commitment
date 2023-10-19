use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::hashing::hasher::Permutation;

#[derive(Clone, Debug)]
pub struct FiatShamir<F: PrimeField, P: Permutation<F>> {
    pub state: P,
    pub input_pos: usize,
    pub output_pos: usize,
    _f: PhantomData<F>,
}

impl<F: PrimeField, P: Permutation<F>> FiatShamir<F, P> {
    pub fn new() -> Self {
        FiatShamir {
            state: P::new(&vec![F::ZERO; P::WIDTH]),
            input_pos: 0,
            output_pos: P::RATE,
            _f: PhantomData,
        }
    }

    pub fn observe_element(&mut self, element: F) {
        self.state[self.input_pos] = element;
        self.input_pos += 1;
        if self.input_pos == P::RATE {
            self.mix();
        }
    }

    pub fn observe_elements(&mut self, elements: &[F]) {
        for &element in elements {
            self.observe_element(element);
        }
    }

    pub fn get_challenge(&mut self) -> F {
        if self.input_pos != 0 || self.output_pos == 0 {
            self.mix();
        }

        self.output_pos -= 1;
        let challenge = self.state[self.output_pos];
        challenge
    }

    pub fn get_challenge_indices(&mut self, n: usize) -> Vec<u64> {
        (0..n)
            .into_iter()
            .map(|_| {
                let challenge = self.get_challenge();
                let index = challenge.into_bigint().into().to_u64_digits()[0];
                index
            })
            .collect()
    }

    fn mix(&mut self) {
        self.state.permute();
        self.output_pos = P::RATE;
        self.input_pos = 0;
    }
}
