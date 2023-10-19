use std::{collections::HashMap, marker::PhantomData};

use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, GeneralEvaluationDomain, EvaluationDomain, DenseUVPolynomial, Polynomial};
use merlin::Transcript;

use crate::{hashing::hasher::Hasher_, merkle_tree::merkle, fri::utils::validate_fri_config, fiat_shamir::fiat_shamir::TranscriptProtocol};

use super::types::{FRIProof, FriConfig, QueryEvalProofs};

pub fn generate_fri_proof<F: PrimeField, H: Hasher_<F>> (polynomial: DensePolynomial<F>, fri_config: FriConfig)
 -> FRIProof<F, H> {
    // last merkle proof generated for length -> blow_up * (2**(last_poly_degree+1))
    // which should be greater than 2**merkle_cap_bits

    let mut transcript = Transcript::new(b"new transcript");

    let coefficients_length = polynomial.coeffs.len();

    assert!(validate_fri_config(&fri_config, coefficients_length as u32-1));

    let blow_up = fri_config.blow_up_factor;

    // let queries: Vec<usize> = T_QUERIES.clone().into();

    // Store merkle roots corresponding to each level
    let mut merkle_roots: Vec<Vec<H::Hash>> = Vec::new();

    // Store merkle objects corresponding to each level (used query by query to generate eval proof)
    let mut merkle_objs: Vec<merkle::MerkleTree<F, H>> = Vec::new();

    // Store all the randomness generated on verifier behalf
    // let mut verifier_rands: Vec<F> = Vec::new();

    // Keeps track of current polynomial on each step of splitting and mixing
    let mut current_polynomial = polynomial.clone();

    // let num_levels = (((coefficients_length as u32)/(fri_config.last_polynomial_degree+1)) as f32).log2() as usize;
    let num_levels = fri_config.level_reductions_bits.len();

    // Keeps track of evaluation and merkle proofs for each query on different levels
    let mut query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>> = Vec::new();

    // store first level original domain ( this will help to get queries to evaluate on for each round )
    let original_domain = coefficients_length * blow_up as usize;

    // last level final evaluation
    let mut final_level_evaluations: Vec<F> = Vec::new();

    // offset for coset-fri, set to the group generator
    let mut offset = F::GENERATOR;

    println!("Generating proof :");
    println!("num levels {:?}", num_levels);
    println!("original domain {:?}", original_domain);

    // Iterate over each level and pre-calculate evaluations and merkles
    println!("---- Iterating through FRI levels : ----");
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
        let query_addition_factor = domain_size/reduction;

        let mut merkle = merkle::MerkleTree::<F,H>::new(fri_config.merkle_cap_bits);

        let mut leaves: Vec<Vec<F>> = Vec::new();

        for domain_idx in 0..query_addition_factor{
            let mut last = domain_idx;
            let mut leaf_evals = Vec::new();
            for _ in 0..reduction { //0..3
                leaf_evals.push(evaluations[last]);
                last += query_addition_factor;
            }   
            leaves.push(leaf_evals);
        }

        merkle.insert(leaves);
        // let merkle = Merkle::<F, H>::new(&evaluations);

        merkle_roots.push(merkle.compute_tree());
        // transcript.observe_element(b"merkle_root", &F::from_le_bytes_mod_order(&merkle.root()));
        let merkle_root_cap_field:Vec<F> = merkle.root_cap.clone().unwrap().iter().map(|r| H::hash_as_field(r.clone())).collect();
        transcript.observe_elements(b"merkle_root", &merkle_root_cap_field);
        merkle_objs.push(merkle);

        // let mut even_coeffs: Vec<F> = Vec::new();
        // let mut odd_coeffs: Vec<F> = Vec::new();
        // let mut new_coeffs: Vec<Vec<F>> = vec![Vec::<F>::new();reduction];//vec![vec![]; 1<<(fri_config.level_reductions_bits[i])];
        let mut new_coeffs: Vec<F> = Vec::new();
        let verifier_rand: F = transcript.get_challenge(b"alpha");
        print!("p --- challenge {:?}-level {:?}", verifier_rand, i);
        for i in (0..coeffs_length).step_by(reduction) {
            // new_coeffs[i%reduction].push(current_polynomial.coeffs[i] * verifier_rand.pow([(i%reduction) as u64]));
            // if i%2==0 {
            //     even_coeffs.push(current_polynomial.coeffs[i]);
            // } else {
            //     odd_coeffs.push(current_polynomial.coeffs[i]);
            // }
            let mut sum = F::ZERO;
            for j in (0..reduction).rev() {
                sum = sum * verifier_rand + current_polynomial.coeffs[i+j];
            }
            new_coeffs.push(sum);
        }
        let mixed_poly: DensePolynomial<F> = DenseUVPolynomial::from_coefficients_vec(new_coeffs);
        // let even_ploy: DensePolynomial<F> = DenseUVPolynomial::from_coefficients_vec(even_coeffs);
        // let odd_poly: DensePolynomial<F> = DensePolynomial::from_coefficients_vec(odd_coeffs);

        // Mixing Polynomials

        //[TODO] replace later by Fiat-Shamir
        // let verifier_rand = F::rand(&mut rng);
        // verifier_rands.push(verifier_rand);
        
        // let mixed_poly = even_ploy.add(odd_poly.mul(verifier_rand));

        current_polynomial = mixed_poly;
        offset = offset.pow([reduction as u64]);
    }
    transcript.observe_elements(b"final evals", &final_level_evaluations);

    // Iterate over each query
    println!("--- Iterating through FRI queries from verifier ---");
    let queries = <Transcript as TranscriptProtocol<F>>::get_challenge_indices(
        &mut transcript,
        b"challenge indices",
        fri_config.num_query as usize
    );
    println!("Queries : {:?}", queries);
    // for i in 0..fri_config.num_query {
    for q_start in queries {
        let mut domain_size_current = original_domain;
        // [TODO] Query should be from fiat shamir
        // let q_init = queries[i as usize];

        let q_init = (q_start as usize)%(original_domain/2);
        for l in 0..num_levels {

            let query_addition_factor = domain_size_current/(1<<fri_config.level_reductions_bits[l]);

            // let mut level_query_set: Vec<usize> = Vec::new();
            // let mut level_evaluation_proofs: merkle::MerkleProof<F,H> = Vec::new();
            let q = q_init%domain_size_current;

            if !query_eval_proofs[l].contains_key(&q) {
                query_eval_proofs[l].insert(
                    q,
                    QueryEvalProofs::<F,H>{
                        merkle_proof: merkle_objs[l].proof(q%(domain_size_current>>fri_config.level_reductions_bits[l])),
                    });
            }
            // for i in 0..(1<<fri_config.level_reductions_bits[l]) {
            //     let tmp = (q + i * query_addition_factor)%domain_size_current;
            //     // level_query_set.push(tmp);
                
            //     // level_evaluation_proofs.push(merkle_objs[l].proof(tmp%(domain_size_current>>fri_config.level_reductions_bits[l])));
            // }

            // if !query_eval_proofs[l].contains_key(&q) {
            //     query_eval_proofs[l].insert(
            //         q,
            //         QueryEvalProofs::<F,H>{
            //             merkle_proof: level_evaluation_proofs,
            //         });
            // }
            domain_size_current = domain_size_current>>fri_config.level_reductions_bits[l];
            // println!("query -- {:?} level {:?} domain_size {:?}", q, l, domain_size_current);
            // let pos_idx = q;
            // let neg_idx = (q + (domain_size_current/2)) % domain_size_current;
            // if !query_eval_proofs[l].contains_key(&pos_idx) {
            //     query_eval_proofs[l].insert(
            //         pos_idx,
            //         QueryEvalProofs::<F,H>{
            //             merkle_proof: merkle_objs[l].proof(pos_idx),
            //             evaluation: merkle_objs[l].leaves[pos_idx]//(pos_idx),
            //         });
            // }
            // if !query_eval_proofs[l].contains_key(&neg_idx) {
            //     query_eval_proofs[l].insert(
            //         neg_idx, 
            //         QueryEvalProofs::<F,H>{
            //             merkle_proof: merkle_objs[l].proof(neg_idx),
            //             evaluation: merkle_objs[l].leaves[neg_idx],
            //         });
            // }
            // domain_size_current/=2;
        }
    }

    FRIProof { 
        final_evaluations: final_level_evaluations, 
        query_eval_proofs,
        level_roots: merkle_roots,
        // verifier_randoms :verifier_rands,
        _h: PhantomData,
    }
 }
