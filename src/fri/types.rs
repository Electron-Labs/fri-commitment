use std::{collections::HashMap, marker::PhantomData};

use ark_ff::PrimeField;

use crate::{hashing::hasher::Hasher_, merkle_tree::merkle};

#[derive(Clone)]
pub struct FriConfig {
    pub num_query: u32,
    pub blow_up_factor: u32,
    pub last_polynomial_degree: u32,
    pub merkle_cap_bits: u32, // merkle proofs roots level
    pub level_reductions_bits: Vec<u32>, // array of bits
}

#[derive(Debug, Clone)]
pub struct QueryEvalProofs<F: PrimeField,H: Hasher_<F>> {
    pub merkle_proof: merkle::MerkleProof<F, H>,
}

#[derive(Debug, Clone)]
pub struct FRIProof<F: PrimeField, H:Hasher_<F>> {
    pub final_evaluations: Vec<F>,
    pub query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>>, // len -> number of rounds
    pub level_roots: Vec<Vec<H::Hash>>,
    pub _h: PhantomData<H>
}
