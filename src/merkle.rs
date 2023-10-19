use ark_ff::PrimeField;

use crate::hasher::Hasher_;

// TODO : generalise for different kind of leaves (hash_n_or_noop (< HASH_OUT size leaves, hash_n_to_m size leaves)
#[derive(Clone)]
pub struct MerkleTree<F: PrimeField, H: Hasher_<F>> {
    pub root_cap: Option<Vec<H::Hash>>,
    levels: Vec<Vec<H::Hash>>, // Precompute hash values at each level
    pub leaves: Vec<Vec<F>>,
    depth: u32,
    merkle_cap_bits: u32, // bits
}

#[derive(Clone, Debug)]
pub struct MerkleProof<F: PrimeField, H: Hasher_<F>> {
    pub leaf: Vec<F>,
    pub leaf_idx: usize,
    // merkle_cap_bits: u32,
    proof: Vec<H::Hash>, // [L1, L2, ...] one neighbour corresponding to each level
    root_cap: Vec<H::Hash>, // indexes of each node to determine left or right direction
}

pub fn merkle_path_verify<F: PrimeField, H: Hasher_<F>>(proof: &MerkleProof<F, H>) -> bool {
    let depth = proof.proof.len();

    let mut curr_idx = proof.leaf_idx;
    // TODO Change point addition when integrate sponge hasher
    let mut computed_val = H::hash(proof.leaf.iter().sum());//proof.leaf;
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
    computed_val == proof.root_cap[curr_idx]
}

impl<F: PrimeField, H: Hasher_<F>> MerkleTree<F, H> {
    // Start a new merkle tree
    pub fn new(merkle_cap_bits: u32) -> Self {
        Self {
                root_cap: None,
                levels: Vec::new(),
                leaves: Vec::new(),
                depth: 0,
                merkle_cap_bits 
            }
    }

    pub fn insert(&mut self, leaves: Vec<Vec<F>>) {
        self.leaves.extend(leaves);
    }

    pub fn compute_tree(&mut self) -> Vec<H::Hash> {
        // Extend len to power of two
        let new_len = self.leaves.len().next_power_of_two();
        self.leaves.resize(new_len, vec![F::ZERO]);

        let num_levels = (new_len as f64).log2() as usize;

        self.depth = num_levels as u32;

        let mut levels: Vec<Vec<H::Hash>> = Vec::new();

        let first_level = self.leaves.iter().map(|l| H::hash(l.iter().sum())).collect();
        levels.push(first_level);

        let last_level = num_levels-self.merkle_cap_bits as usize;

        assert!(last_level >= 1);

        for i in 0..last_level {
            let current_layer = levels[i].clone();
            let next_layer = current_layer.chunks(2).map(|ips|{// [TODO] change 2 to arity
                H::hash_two_to_one(ips[0], ips[1])
            }).collect::<Vec<H::Hash>>();
            levels.push(next_layer);
        }
        self.levels = levels;
        assert_eq!(self.levels[last_level].len(), (2 as usize).pow(self.merkle_cap_bits as u32)); // Top most level will always have one value [TODO] replace with CAP
        self.root_cap = Some(self.levels[last_level].clone());
        self.levels[last_level].clone()
    }

    pub fn proof(&self, idx: usize) -> MerkleProof<F, H>{
        let leaf_val = self.leaves[idx].clone();
        // proof: Vec<F>, // [L1, L2, ...] one neighbour corresponding to each level // length will be depth
        let mut proof: Vec<H::Hash> = Vec::new();
        let mut curr_idx = idx;
        let last_level = self.depth-self.merkle_cap_bits as u32;
        for i in 0..last_level {
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
            root_cap: self.root_cap.clone().unwrap(),
            // merkle_cap_bits: self.merkle_cap_bits
        }

    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{goldilocks_field::Fq, hasher::Sha256_};
    #[test]
    fn test_merkle() {
        let mut tree = MerkleTree::<Fq, Sha256_<Fq>>::new(2);

        let num_leaves = 16;

        let leaf: Vec<Fq> = (0..4).map(|i| Fq::from(i as u32)).collect();

        let leaves: Vec<Vec<Fq>> = (0..num_leaves).map(|i| leaf.iter().map(|l| l.clone()*Fq::from(i)).collect::<Vec<Fq>>()).collect();

        tree.insert(leaves);

        let root = tree.compute_tree();

        println!("root {:?}", root);

        let merkle_proof = tree.proof(1);

        let verify = merkle_path_verify(&merkle_proof);
        println!("verify : {:?}", verify);
    }
}