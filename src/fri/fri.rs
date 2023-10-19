use std::collections::HashMap;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_poly::{polynomial::univariate::DensePolynomial, EvaluationDomain, Polynomial};

use ark_poly::{GeneralEvaluationDomain, evaluations};
use ark_poly::DenseUVPolynomial;
use ark_std::ops::{Mul, Add};
use merlin::Transcript;

use crate::fiat_shamir::fiat_shamir::TranscriptProtocol;
use crate::hashing::hasher::Hasher_;
// use crate::merkle_tree::{MerkleProof_, MerkleTrait, Merkle, merkle_path_verify};
use crate::fields::goldilocks_field::Fq;

use crate::merkle_tree::merkle::{self, merkle_path_verify};

// const T_QUERIES: [usize; 4] = [1,2,5,7];

#[derive(Clone)]
pub struct FriConfig {
    num_query: u32,
    blow_up_factor: u32,
    last_polynomial_degree: u32,
    merkle_cap_bits: u32,
    level_reductions_bits: Vec<u32>, // array of bits
}

#[derive(Debug, Clone)]
pub struct QueryEvalProofs<F: PrimeField,H: Hasher_<F>> {
    merkle_proof: merkle::MerkleProof<F, H>,
}

#[derive(Debug, Clone)]
pub struct FRIProof<F: PrimeField, H:Hasher_<F>> {
    final_evaluations: Vec<F>,
    query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>>, // len -> number of rounds
    level_roots: Vec<Vec<H::Hash>>,
    _h: PhantomData<H>
}

pub fn validate_fri_config (fri_config: &FriConfig, poly_degree: u32) -> bool {
    
    assert!(fri_config.blow_up_factor * (1<<fri_config.last_polynomial_degree+1) >= 1<<(fri_config.merkle_cap_bits+1), "Invalid FRI params (merkle cap)");

    let redns = fri_config.level_reductions_bits.clone();
    let mut curr_deg = poly_degree;
    for i in 0..redns.len(){
        if curr_deg <= fri_config.last_polynomial_degree {
            return true;
        }
        curr_deg = curr_deg>>redns[i];
    }

    curr_deg <= fri_config.last_polynomial_degree
}

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

pub fn verify_fri_proof<F: PrimeField + std::convert::From<i32>, H: Hasher_<F>> (fri_config: FriConfig, degree: u32, fri_proof: FRIProof<F,H>) -> bool {
    println!("--- Verifying FRI LDE check for degree {:?} ---", degree);
    // let queries: Vec<usize> = T_QUERIES.clone().into();

    let final_evaluations = fri_proof.final_evaluations;

    let final_evalutaion_degree = fri_config.last_polynomial_degree;

    let eval_proofs = fri_proof.query_eval_proofs;
    let level_roots = fri_proof.level_roots;

    let mut transcript = Transcript::new(b"new transcript");

    let mut verifier_randoms = vec![];
    for root in level_roots.iter() {
        let merkle_root_cap_field:Vec<F> = root.iter().map(|r| H::hash_as_field(r.clone())).collect();
        transcript.observe_elements(b"merkle_root", &merkle_root_cap_field);
        let verifier_rand: F = transcript.get_challenge(b"alpha");
        verifier_randoms.push(verifier_rand);
    }

    transcript.observe_elements(b"final evals", &final_evaluations);
    let queries = <Transcript as TranscriptProtocol<F>>::get_challenge_indices(
        &mut transcript,
        b"challenge indices",
        fri_config.num_query as usize
    );


    let original_domain_size = fri_config.blow_up_factor * (degree+1);
    // let levels_to_iterate = (((degree+1)/(final_evalutaion_degree+1)) as f32).log2() as usize;
    let levels_to_iterate = fri_config.level_reductions_bits.len();

    println!("original domain size {:?}", original_domain_size);
    println!("levels to iterate {:?}", levels_to_iterate);

    let mut final_offset = F::GENERATOR;
    for exp in fri_config.level_reductions_bits.clone() {
        final_offset = final_offset.pow([exp as u64]);
    }
    // for _ in 0..levels_to_iterate {
    //     final_offset = final_offset * final_offset;
    // }

    assert_eq!(final_evaluations.len() as u32, fri_config.blow_up_factor*(fri_config.last_polynomial_degree+1));
    
    let mut final_evaluation_degree_correct = true;
    if final_evalutaion_degree == 0 {
        for i in 1..final_evaluations.len(){
            final_evaluation_degree_correct = final_evaluations[i] == final_evaluations[i-1];
        }
    } else {
        let mut eval_domain: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(final_evaluations.len()).unwrap();
        eval_domain = eval_domain.get_coset(final_offset).expect("Error in getting coset");
        let coeffs = eval_domain.ifft(&final_evaluations);
        let final_eval_poly_degree = coeffs.len();
        final_evaluation_degree_correct = final_eval_poly_degree as u32 <= (fri_config.last_polynomial_degree+1) * fri_config.blow_up_factor;
        println!("{}", final_eval_poly_degree);
    }
    assert!(final_evaluation_degree_correct);

    println!("*** Verifying evaluation proof and consistency checks for each query ***");
    // for i in 0..fri_config.num_query {
    for q_start in queries {
        // println!("Starting to verify query -- {:?}", i+1);
        println!("Starting to verify query -- {:?}", q_start);
        let mut domain_size_current = original_domain_size as usize;
        // let q_init = queries[i as usize];
        let q_init = (q_start as usize)%(domain_size_current/2);
        let mut next_level_value: F = F::one();
        let mut offset = F::GENERATOR;
        for l in 0..levels_to_iterate {
            let reduction = 1<<fri_config.level_reductions_bits[l];
            let q = q_init%domain_size_current;
            println!("Verifying query {:?} at level {:?}",q,l);

            let query_addition_factor = domain_size_current/reduction;

            let mut level_query_set: Vec<usize> = Vec::new();

            for i in 0..(1<<fri_config.level_reductions_bits[l]) {
                let tmp = (q + i * query_addition_factor)%domain_size_current;
                level_query_set.push(tmp);
            }
            level_query_set.sort();
            println!("level::{}, query_set::{:?}", l, level_query_set);
            let eval_proof = eval_proofs[l].get(&q).unwrap();

            let evaluations = eval_proof.merkle_proof.leaf.clone();
            println!("query: {}, reduction: {}, next_level_value: {:?}\nevaluations: {:?}", q, reduction, next_level_value, evaluations);

            if l !=0 {
                // check prev round to current round consistency
                assert_eq!(next_level_value, evaluations[q/reduction], "Consistency check failed for query {:?} between levels {:?} and {:?}", q, l-1, l);
            }

            assert!(merkle_path_verify::<F,H>(&eval_proof.merkle_proof)); 

            // let evaluations = eval_proof.merkle_proof
            // let evaluations: Vec<F> = eval_proof.merkle_proof.iter().zip(level_query_set.clone()).map(|(p, lq)| {
            //     assert!(merkle_path_verify::<F,H>(&p)); 
            //     assert_eq!(p.leaf_idx, lq);
            //     p.leaf
            // }).collect();

            let mut eval_domain_verifier: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(domain_size_current).unwrap();
            eval_domain_verifier = eval_domain_verifier.get_coset(offset).expect("Error in getting coset");

            let verifier_rand = verifier_randoms[l];
            let l_x: F = level_query_set.iter().map(|&i_l| {
                let d = eval_domain_verifier.element(i_l);
                verifier_rand-d
            })
            .product();
            let barycentric_weights = level_query_set
                .iter()
                .map(|&i_l| {
                    level_query_set
                        .iter()
                        .filter(|&&j_l| j_l != i_l)
                        .map(|j_l| {
                            eval_domain_verifier.element(i_l) - eval_domain_verifier.element(*j_l)
                        })
                        .product()
                })
                .collect::<Vec<F>>();

            let mut interpolate = F::ZERO;
            for i in 0..level_query_set.len() {
                let t = evaluations[i] / ((verifier_rand-eval_domain_verifier.element(level_query_set[i])) * barycentric_weights[i]);
                interpolate += t;
            }
            interpolate *= l_x;
            next_level_value = interpolate;

            // let pos_idx = q;
            // let neg_idx = (q + (domain_size_current/2)) % domain_size_current;
            // // verify positive point
            // let pos_eval_proof = eval_proofs[l].get(&pos_idx).unwrap();
            
            
            // // assert!(merkle_path_verify::<F,H>(&level_roots[l], pos_idx, pos_eval_proof.evaluation, domain_size_current, &pos_eval_proof.merkle_proof));
            // assert!(merkle_path_verify::<F,H>(&pos_eval_proof.merkle_proof));

            // // verify negative point
            // let neg_eval_proof = eval_proofs[l].get(&neg_idx).unwrap();
            // // assert!(merkle_path_verify::<F,H>(&level_roots[l], neg_idx, neg_eval_proof.evaluation, domain_size_current, &neg_eval_proof.merkle_proof));
            // assert!(merkle_path_verify::<F,H>(&neg_eval_proof.merkle_proof));

            
            // let denom = eval_domain_verifier.element(pos_idx) * F::from(2);
            // next_level_value = 
            //     // (((pos_eval_proof.evaluation+neg_eval_proof.evaluation))/(F::from(2))) + (fri_proof.verifier_randoms[l]*((pos_eval_proof.evaluation-neg_eval_proof.evaluation)/denom));
            //     (((pos_eval_proof.evaluation+neg_eval_proof.evaluation))/(F::from(2))) + (verifier_randoms[l]*((pos_eval_proof.evaluation-neg_eval_proof.evaluation)/denom));
            // domain_size_current/=2;
            domain_size_current = domain_size_current>>fri_config.level_reductions_bits[l];
            // offset = offset * offset;
            offset = offset.pow([reduction as u64]);
        }
        // match value from evaluations
        // let q_final = queries[i as usize]%domain_size_current;
        let q_final = (q_start as usize)%(domain_size_current);
        assert_eq!(final_evaluations[q_final], next_level_value);
    }
    true
}


#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254::Fr;
    use crate::hashing::hasher::Sha256_;
    #[test]
    pub fn test_(){
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fq> = coeff_u64.iter().map(|x| Fq::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fq> = DenseUVPolynomial::from_coefficients_vec(coeffs);

        let fri_config = FriConfig { num_query: 4, blow_up_factor: 2, last_polynomial_degree: 0 , merkle_cap_bits: 1, level_reductions_bits: todo!() };

        let fri_proof = generate_fri_proof::<Fq, Sha256_<Fq>>(poly, fri_config.clone());
        
        assert!(verify_fri_proof(fri_config, (coeff_u64.len()-1) as u32, fri_proof))
    }

    #[test]
    pub fn test_1(){
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fq> = coeff_u64.iter().map(|x| Fq::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fq> = DenseUVPolynomial::from_coefficients_vec(coeffs);

        let fri_config = FriConfig { num_query: 1, blow_up_factor: 2, last_polynomial_degree: 0 , merkle_cap_bits: 0, level_reductions_bits: vec![2,1] };

        let fri_proof = generate_fri_proof::<Fq, Sha256_<Fq>>(poly, fri_config.clone());
        
        println!("FRI PROOF: {:#?}", fri_proof);

        assert!(verify_fri_proof(fri_config, (coeff_u64.len()-1) as u32, fri_proof))
    }

    #[test]
    #[should_panic]
    pub fn test_2(){
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10, 19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fq> = coeff_u64.iter().map(|x| Fq::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fq> = DenseUVPolynomial::from_coefficients_vec(coeffs);

        let fri_config = FriConfig { num_query: 4, blow_up_factor: 2, last_polynomial_degree: 0 , merkle_cap_bits: 2, level_reductions_bits: todo!() };

        let fri_proof = generate_fri_proof::<Fq, Sha256_<Fq>>(poly, fri_config.clone());
        
        assert!(verify_fri_proof(fri_config, (coeff_u64.len()-1) as u32, fri_proof))
    }

    #[test]
    pub fn test_3() {
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10, 19, 56, 34, 48,43,37, 10, 10, 19, 56, 34, 48,43,37, 10, 10, 19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fq> = coeff_u64.iter().map(|x| Fq::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fq> = DenseUVPolynomial::from_coefficients_vec(coeffs);

        let fri_config = FriConfig { num_query: 4, blow_up_factor: 2, last_polynomial_degree: 3 , merkle_cap_bits: 2, level_reductions_bits: todo!() };

        let fri_proof = generate_fri_proof::<Fq, Sha256_<Fq>>(poly, fri_config.clone());
        
        assert!(verify_fri_proof(fri_config, (coeff_u64.len()-1) as u32, fri_proof))
    }
}