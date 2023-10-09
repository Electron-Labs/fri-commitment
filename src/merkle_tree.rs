use std::marker::PhantomData;

use ark_ff::PrimeField;

use crate::hasher::Hasher_;

use rs_merkle::{MerkleTree, MerkleProof};
use rs_merkle::algorithms::Sha256;

#[derive(Clone)]
pub struct Merkle<F: PrimeField, H: Hasher_<F>> {
    leaves: Vec<F>,
    mt: MerkleTree<Sha256>,
    _h: PhantomData<H>
}

#[derive(Debug)]
pub struct MerkleProof_<T> {
    pub proof: Vec<T>
}

pub trait MerkleTrait<F: PrimeField, H: Hasher_<F>> {
    fn new(leaves: &Vec<F>) -> Self;
    fn root(&self) -> [u8; 32];
    fn proof(&self, idx: usize) -> MerkleProof_<[u8; 32]>;
    fn get_leaf(&self, idx: usize) -> F;
}

impl<F: PrimeField, H: Hasher_<F>> MerkleTrait<F,H> for Merkle<F, H> {
    fn new(leaves: &Vec<F>) -> Self {
        let leaves_input: Vec<[u8; 32]> = leaves.iter().map(|l| return H::hash(l.clone())).collect();
        let mt = MerkleTree::<Sha256>::from_leaves(&leaves_input);
        Self { 
            leaves: leaves.clone(), 
            mt,
            _h: PhantomData, 
        }
    }

    fn root(&self) -> [u8; 32] {
        self.mt.root().unwrap()
    }

    fn proof(&self, idx: usize) -> MerkleProof_<[u8; 32]> {
        MerkleProof_ {
            proof: self.mt.proof(&[idx]).proof_hashes().to_vec(),
        }
        
    }

    fn get_leaf(&self, idx: usize) -> F {
        self.leaves.get(idx).unwrap().clone()
    }
} 

pub fn merkle_path_verify<F: PrimeField, H: Hasher_<F>> 
    (root: &[u8; 32], leaf_idx: usize, leaf: F, total_leaves: usize, proof: &MerkleProof_<[u8; 32]>)
 -> bool {
    let mp = MerkleProof::<Sha256>::new(proof.proof.clone());
    let leaf_hash_val = H::hash(leaf);
    mp.verify(root.clone(), &[leaf_idx], &[leaf_hash_val], total_leaves)
}