use std::{collections::HashMap, marker::PhantomData};

use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, GeneralEvaluationDomain, EvaluationDomain, DenseUVPolynomial, Polynomial};

use crate::{hashing::hasher::{Hasher_, Permutation}, merkle_tree::merkle, fri::utils::validate_fri_config, fiat_shamir::fiat_shamir::FiatShamir};

use super::types::{FRIProof, FriConfig, QueryEvalProofs};

// Groups the domain indexes so that they can be grouped together by their parities
pub fn leaf_groupings(reduction_bits: Vec<u32>, start_domain: usize, num_levels: usize) -> Vec<Vec<usize>>{
    // stores arrays for each level which can be grouped together by their respective reduction sizes.
    let mut groupings: Vec<Vec<usize>> = vec![Vec::new(); num_levels];//Vec::with_capacity(num_levels);
    let mut domain_size = start_domain;
    for level in 0..num_levels{
        let reduction = 1<<reduction_bits[level];
        let query_addition_factor = domain_size/reduction;
        for domain_idx in 0..query_addition_factor {
            groupings[level].push(domain_idx);
            for _ in 0..reduction-1{
                let val = groupings[level].last().unwrap().clone();
                groupings[level].push(val+query_addition_factor);
            }
        }
        domain_size = domain_size>>reduction_bits[level];
    }
    println!("groupings {:?}", groupings);
    groupings
}

pub fn fold_polynomial<F:PrimeField>(polynomial: DensePolynomial<F>, rand: F, reduction: usize) ->DensePolynomial<F> {
    let mut folded_coeffs: Vec<F> = Vec::new();
    for i in (0..polynomial.coeffs.len()).step_by(reduction) {
        let mut sum = F::ZERO;
        for j in (0..reduction).rev() {
            sum = sum * rand + polynomial.coeffs[i+j];
        }
        folded_coeffs.push(sum);
    }
    DenseUVPolynomial::from_coefficients_vec(folded_coeffs)
}

// Generate query proofs for a corresponding query at each FRI level
pub fn generate_query_eval_proofs<F: PrimeField, H: Hasher_<F>>(queries: Vec<u64>, original_domain: usize, reduction_bits: Vec<u32>, merkle_objs: &Vec<merkle::MerkleTree<F, H>>, query_eval_proofs: &mut Vec<HashMap<usize, QueryEvalProofs<F, H>>>) {
    for q_start in queries {
        let mut domain_size_current = original_domain;
        // We translate each query to first half of its domain
        let q_init = (q_start as usize)%(original_domain/2);
        for l in 0..reduction_bits.len() {
            let q = q_init%domain_size_current;
            let next_domain_size = domain_size_current>>reduction_bits[l];
            if !query_eval_proofs[l].contains_key(&q) {
                query_eval_proofs[l].insert(
                    q,
                    QueryEvalProofs::<F,H>{
                        merkle_proof: merkle_objs[l].proof(q%next_domain_size),
                    });
            }
            domain_size_current = next_domain_size;
        }
    }
}

pub fn generate_fri_proof<F: PrimeField, H: Hasher_<F>, P: Permutation<F>> (polynomial: DensePolynomial<F>, fri_config: FriConfig)
 -> FRIProof<F, H> {
    let mut fiat_shamir_transform: FiatShamir<F, P> = FiatShamir::new();

    let coefficients_length = polynomial.coeffs.len();

    assert!(validate_fri_config(&fri_config, coefficients_length as u32-1));

    let blow_up = fri_config.blow_up_factor;

    // Store merkle roots corresponding to each level
    let mut merkle_roots: Vec<Vec<H::Hash>> = Vec::new();

    // Store merkle objects corresponding to each level (used query by query to generate eval proof)
    let mut merkle_objs: Vec<merkle::MerkleTree<F, H>> = Vec::new();

    // Keeps track of current polynomial on each step of splitting and mixing
    let mut current_polynomial = polynomial.clone();

    // Num of levels for which fri reduction is to be performed would be same as length of level reduction bits provided
    let num_levels = fri_config.level_reductions_bits.len();

    // Keeps track of evaluation and merkle proofs for each query on different levels
    let mut query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>> = Vec::new();

    // store first level original domain ( this will help to get queries to evaluate on for each round )
    let original_domain = coefficients_length * blow_up as usize;

    // last level final evaluation
    // [TODO] Send polynomial coefficients instead of evals
    // Saves verifier from a LDE check
    let mut final_level_evaluations: Vec<F> = Vec::new();

    // offset for coset-fri, set to the group generator
    let mut offset = F::GENERATOR;

    println!("Generating proof :");
    println!("num levels {:?}", num_levels);
    println!("original domain size{:?}", original_domain);

    // Iterate over each level and pre-calculate evaluations and merkles
    println!("---- Iterating through FRI levels : ----");

    let leaf_groupings = leaf_groupings(fri_config.level_reductions_bits.clone(), original_domain, num_levels);

    for i in 0..num_levels+1 {
        println!("*** Level {:?} ***", i);
        let eval_proof = HashMap::new();
        query_eval_proofs.push(eval_proof);

        let coeffs_length = current_polynomial.coeffs.len();
        println!("coefficient length : {:?}", coeffs_length);

        // 1. Get evaluation domain (roots of unity multiplicative subroup size)
        let domain_size = coeffs_length * blow_up as usize;
        let mut eval_domain: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(domain_size).unwrap();
        eval_domain = eval_domain.get_coset(offset).expect("Error in getting coset");
        println!("domain size : {:?}", domain_size);
        // 2. Generate evaluations over the eval_domain
        let evaluations: Vec<F> = eval_domain.elements().map(|d| return current_polynomial.evaluate(&d)).collect();
        println!("level: {}, evaluations: {:?}", i, evaluations);

        if i==num_levels {
            // final level evaluations
            println!("Reached till final polynomial degree {:?}", current_polynomial.degree());
            final_level_evaluations = evaluations;
            break;
        }

        let reduction = 1<<fri_config.level_reductions_bits[i];

        let mut merkle = merkle::MerkleTree::<F,H>::new(fri_config.merkle_cap_bits);

        let mut leaves: Vec<Vec<F>> = Vec::new();

        leaf_groupings[i].chunks(reduction).for_each(|leaf| {
            let leaf_element: Vec<F> = leaf.iter().map(|l| evaluations[l.clone()]).collect();
            leaves.push(leaf_element);
        });

        merkle.insert(leaves);

        merkle_roots.push(merkle.compute_tree());
        
        let merkle_root_cap_field:Vec<F> = merkle.root_cap.clone().unwrap().iter().map(|r| H::hash_as_field(r.clone())).collect();
        fiat_shamir_transform.observe_elements(&merkle_root_cap_field);
        merkle_objs.push(merkle);

        let verifier_rand: F = fiat_shamir_transform.get_challenge();

        current_polynomial = fold_polynomial(current_polynomial, verifier_rand, reduction);

        offset = offset.pow([reduction as u64]);
    }

    fiat_shamir_transform.observe_elements(&final_level_evaluations);

    // Iterate over each query
    println!("--- Iterating through FRI queries from verifier ---");
    let queries = fiat_shamir_transform.get_challenge_indices(fri_config.num_query as usize);
    println!("Queries : {:?}", queries);
    
    // Generate query proofs
    generate_query_eval_proofs::<F,H>(queries, original_domain, fri_config.level_reductions_bits, &merkle_objs, &mut query_eval_proofs);

    FRIProof { 
        final_evaluations: final_level_evaluations, 
        query_eval_proofs,
        level_roots: merkle_roots,
        _h: PhantomData,
    }
 }
