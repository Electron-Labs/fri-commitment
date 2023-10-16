use ark_ff::PrimeField;

use crate::hasher::Hasher_;

// TODO : generalise for different kind of leaves (hash_n_or_noop (< HASH_OUT size leaves, hash_n_to_m size leaves)
pub struct MerkleTree<F: PrimeField, H: Hasher_<F>> {
    pub root: Option<H::Hash>,
    levels: Vec<Vec<H::Hash>>, // Precompute hash values at each level
    pub leaves: Vec<F>,
    depth: u32,
}

#[derive(Debug)]
pub struct MerkleProof<F: PrimeField, H: Hasher_<F>> {
    leaf: F,
    leaf_idx: usize,
    proof: Vec<H::Hash>, // [L1, L2, ...] one neighbour corresponding to each level
    root: H::Hash, // indexes of each node to determine left or right direction
}

pub fn merkle_path_verify<F: PrimeField, H: Hasher_<F>>(proof: &MerkleProof<F, H>) -> bool {
    let depth = proof.proof.len();

    let mut curr_idx = proof.leaf_idx;
    let mut computed_val = H::hash(proof.leaf);//proof.leaf;
    // compute root
    for i in 0..depth {
        if curr_idx%2 == 0 {
            // we have l node
            let neighbour = proof.proof[i as usize]; // extracted right node
            computed_val = H::hash_two_to_one(computed_val, neighbour);
            curr_idx = curr_idx/2;
        } else {
            // we have r node
            let neighbour = proof.proof[i as usize];
            computed_val = H::hash_two_to_one(neighbour, computed_val); // extracted left
            curr_idx = (curr_idx-1)/2;
        }
    }
    computed_val == proof.root
}

impl<F: PrimeField, H: Hasher_<F>> MerkleTree<F, H> {
    // Start a new merkle tree
    pub fn new() -> Self {
        Self {
                root: None,
                levels: Vec::new(),
                leaves: Vec::new(),
                depth: 0,
            }
    }

    pub fn insert(&mut self, leaves: &[F]) {
        self.leaves.extend(leaves);
    }

    pub fn compute_tree(&mut self) -> H::Hash {
        // Extend len to power of two
        let new_len = self.leaves.len().next_power_of_two();
        self.leaves.resize(new_len, F::ZERO);

        let num_levels = (new_len as f64).log2() as usize;

        self.depth = num_levels as u32;

        let mut levels: Vec<Vec<H::Hash>> = Vec::new();

        let first_level = self.leaves.iter().map(|l| H::hash(l.clone())).collect();
        levels.push(first_level);

        for i in 0..num_levels {
            let current_layer = levels[i].clone();
            let next_layer = current_layer.chunks(2).map(|ips|{// [TODO] change 2 to arity
                H::hash_two_to_one(ips[0], ips[1])
            }).collect::<Vec<H::Hash>>();
            levels.push(next_layer);
        }
        self.levels = levels;
        assert_eq!(self.levels[num_levels].len(), 1); // Top most level will always have one value [TODO] replace with CAP
        self.root = Some(self.levels[num_levels][0]);
        self.levels[num_levels][0]
    }

    pub fn proof(&self, idx: usize) -> MerkleProof<F, H>{
        let leaf_val = self.leaves[idx];
        // proof: Vec<F>, // [L1, L2, ...] one neighbour corresponding to each level // length will be depth
        let mut proof: Vec<H::Hash> = Vec::new();
        let mut curr_idx = idx;
        for i in 0..self.depth {
            if curr_idx%2 == 0 {
                // we have l node
                let neighbour = self.levels[i as usize][curr_idx+1];
                proof.push(neighbour);
                curr_idx = curr_idx/2;
            } else {
                // we have r node
                let neighbour = self.levels[i as usize][curr_idx-1];
                proof.push(neighbour);
                curr_idx = (curr_idx-1)/2;
            }
        }
        MerkleProof{
            leaf: leaf_val,
            leaf_idx: idx,
            proof,
            root: self.root.unwrap(),
        }

    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{goldilocks_field::Fq, hasher::Sha256_};
    #[test]
    fn test_merkle() {
        let mut tree = MerkleTree::<Fq, Sha256_<Fq>>::new();

        let num_leaves = 10;
        let leaves: Vec<Fq> = (0..num_leaves).map(|i| Fq::from(i as u32)).collect();

        tree.insert(&leaves);

        let root = tree.compute_tree();

        let merkle_proof = tree.proof(2);

        let verify = merkle_path_verify(&merkle_proof);
        println!("verify : {:?}", verify);
    }
}