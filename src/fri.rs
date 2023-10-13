use std::collections::HashMap;
use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_poly::{polynomial::univariate::DensePolynomial, EvaluationDomain, Polynomial};

use ark_poly::GeneralEvaluationDomain;
use ark_poly::DenseUVPolynomial;
use ark_std::ops::{Mul, Add};
use merlin::Transcript;

use crate::fiat_shamir::TranscriptProtocol;
use crate::hasher::Hasher_;
use crate::merkle_tree::{MerkleProof_, MerkleTrait, Merkle, merkle_path_verify};
use crate::goldilocks_field::Fq;

// const T_QUERIES: [usize; 4] = [1,2,5,7];

#[derive(Clone)]
pub struct FriConfig {
    num_query: u32,
    blow_up_factor: u32,
    last_polynomial_degree: u32,
}

#[derive(Debug)]
pub struct QueryEvalProofs<F: PrimeField,H: Hasher_<F>> {
    merkle_proof: MerkleProof_<[u8; 32]>,
    evaluation: F,
    _h: PhantomData<H>
}

#[derive(Debug)]
pub struct FRIProof<F: PrimeField, H:Hasher_<F>> {
    final_evaluations: Vec<F>,
    query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>>, // len -> number of rounds
    level_roots: Vec<[u8; 32]>,
    // verifier_randoms: Vec<F>,
    _h: PhantomData<H>
}

pub fn generate_fri_proof<F: PrimeField, H: Hasher_<F>> (polynomial: DensePolynomial<F>, fri_config: FriConfig)
 -> FRIProof<F, H> {
    // let mut rng = ark_std::test_rng();
    let mut transcript = Transcript::new(b"new transcript");

    let coefficients_length = polynomial.coeffs.len();

    let blow_up = fri_config.blow_up_factor;

    // let queries: Vec<usize> = T_QUERIES.clone().into();

    // Store merkle roots corresponding to each level
    let mut merkle_roots: Vec<[u8; 32]> = Vec::new();

    // Store merkle objects corresponding to each level (used query by query to generate eval proof)
    let mut merkle_objs: Vec<Merkle<F, H>> = Vec::new();

    // Store all the randomness generated on verifier behalf
    // let mut verifier_rands: Vec<F> = Vec::new();

    // Keeps track of current polynomial on each step of splitting and mixing
    let mut current_polynomial = polynomial.clone();

    let num_levels = (((coefficients_length as u32)/(fri_config.last_polynomial_degree+1)) as f32).log2() as usize;

    // Keeps track of evaluation and merkle proofs for each query on different levels
    let mut query_eval_proofs: Vec<HashMap<usize, QueryEvalProofs<F,H>>> = Vec::new();

    // store first level original domain ( this will help to get queries to evaluate on for each round )
    let original_domain = coefficients_length * blow_up as usize;

    // last level final evaluation
    let mut final_level_evaluations: Vec<F> = Vec::new();

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
        let eval_domain: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(domain_size).unwrap();
        println!("domain size : {:?}", domain_size);
        // 2. Generate evaluations over the eval_domain
        let evaluations: Vec<F> = eval_domain.elements().map(|d| return current_polynomial.evaluate(&d)).collect();

        if i==num_levels {
            // final level evaluations
            println!("Reached till final polynomial degree {:?}", current_polynomial.degree());
            final_level_evaluations = evaluations;
            break;
        }

        let merkle = Merkle::<F, H>::new(&evaluations);
        merkle_roots.push(merkle.root());
        transcript.observe_element(b"merkle_root", &F::from_le_bytes_mod_order(&merkle.root()));
        merkle_objs.push(merkle);

        let mut even_coeffs: Vec<F> = Vec::new();
        let mut odd_coeffs: Vec<F> = Vec::new();
        for i in 0..coeffs_length {
            if i%2==0 {
                even_coeffs.push(current_polynomial.coeffs[i]);
            } else {
                odd_coeffs.push(current_polynomial.coeffs[i]);
            }
        }
        let even_ploy: DensePolynomial<F> = DenseUVPolynomial::from_coefficients_vec(even_coeffs);
        let odd_poly: DensePolynomial<F> = DensePolynomial::from_coefficients_vec(odd_coeffs);

        //[TODO] replace later by Fiat-Shamir
        // let verifier_rand = F::rand(&mut rng);
        // verifier_rands.push(verifier_rand);
        let verifier_rand: F = transcript.get_challenge(b"alpha");
        let mixed_poly = even_ploy.add(odd_poly.mul(verifier_rand));

        current_polynomial = mixed_poly;
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
            let q = q_init%domain_size_current;
            println!("query -- {:?} level {:?} domain_size {:?}", q, l, domain_size_current);
            let pos_idx = q;
            let neg_idx = (q + (domain_size_current/2)) % domain_size_current;
            if !query_eval_proofs[l].contains_key(&pos_idx) {
                query_eval_proofs[l].insert(
                    pos_idx,
                    QueryEvalProofs::<F,H>{
                        merkle_proof: merkle_objs[l].proof(pos_idx),
                        evaluation: merkle_objs[l].get_leaf(pos_idx),
                        _h: PhantomData,
                    });
            }
            if !query_eval_proofs[l].contains_key(&neg_idx) {
                query_eval_proofs[l].insert(
                    neg_idx, 
                    QueryEvalProofs::<F,H>{
                        merkle_proof: merkle_objs[l].proof(neg_idx),
                        evaluation: merkle_objs[l].get_leaf(neg_idx),
                        _h: PhantomData,
                    });
            }
            domain_size_current/=2;
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
        transcript.observe_element(b"merkle_root", &F::from_le_bytes_mod_order(root));
        let verifier_rand: F = transcript.get_challenge(b"alpha");
        verifier_randoms.push(verifier_rand);
    }

    transcript.observe_elements(b"final evals", &final_evaluations);
    let queries = <Transcript as TranscriptProtocol<F>>::get_challenge_indices(
        &mut transcript,
        b"challenge indices",
        fri_config.num_query as usize
    );

    assert_eq!(final_evaluations.len() as u32, fri_config.blow_up_factor*(fri_config.last_polynomial_degree+1));
    
    let mut final_evaluation_degree_correct = true;
    if final_evalutaion_degree == 0 {
        for i in 1..final_evaluations.len(){
            final_evaluation_degree_correct = final_evaluations[i] == final_evaluations[i-1];
        }
    } else {
        let eval_domain: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(final_evaluations.len()).unwrap();
        let coeffs = eval_domain.ifft(&final_evaluations);
        let final_eval_poly_degree = coeffs.len();
        final_evaluation_degree_correct = final_eval_poly_degree as u32 <= (fri_config.last_polynomial_degree+1) * fri_config.blow_up_factor;
        println!("{}", final_eval_poly_degree);
    }
    assert!(final_evaluation_degree_correct);

    let original_domain_size = fri_config.blow_up_factor * (degree+1);
    let levels_to_iterate = (((degree+1)/(final_evalutaion_degree+1)) as f32).log2() as usize;

    println!("original domain size {:?}", original_domain_size);
    println!("levels to iterate {:?}", levels_to_iterate);

    println!("*** Verifying evaluation proof and consistency checks for each query ***");
    // for i in 0..fri_config.num_query {
    for q_start in queries {
        // println!("Starting to verify query -- {:?}", i+1);
        println!("Starting to verify query -- {:?}", q_start);
        let mut domain_size_current = original_domain_size as usize;
        // let q_init = queries[i as usize];
        let q_init = (q_start as usize)%(domain_size_current/2);
        let mut next_level_value: F = F::one();
        for l in 0..levels_to_iterate {
            let q = q_init%domain_size_current;
            println!("Verifying query {:?} at level {:?}",q,l);
            let pos_idx = q;
            let neg_idx = (q + (domain_size_current/2)) % domain_size_current;
            // verify positive point
            let pos_eval_proof = eval_proofs[l].get(&pos_idx).unwrap();
            if l !=0 {
                // check prev round to current round consistency
                assert_eq!(next_level_value, pos_eval_proof.evaluation, "Consistency check failed for query {:?} between levels {:?} and {:?}", q, l-1, l);
            }
            
            assert!(merkle_path_verify::<F,H>(&level_roots[l], pos_idx, pos_eval_proof.evaluation, domain_size_current, &pos_eval_proof.merkle_proof));

            // verify negative point
            let neg_eval_proof = eval_proofs[l].get(&neg_idx).unwrap();
            assert!(merkle_path_verify::<F,H>(&level_roots[l], neg_idx, neg_eval_proof.evaluation, domain_size_current, &neg_eval_proof.merkle_proof));

            let eval_domain_verifier: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(domain_size_current).unwrap();
            let denom = eval_domain_verifier.element(pos_idx) * F::from(2);
            next_level_value = 
                // (((pos_eval_proof.evaluation+neg_eval_proof.evaluation))/(F::from(2))) + (fri_proof.verifier_randoms[l]*((pos_eval_proof.evaluation-neg_eval_proof.evaluation)/denom));
                (((pos_eval_proof.evaluation+neg_eval_proof.evaluation))/(F::from(2))) + (verifier_randoms[l]*((pos_eval_proof.evaluation-neg_eval_proof.evaluation)/denom));
            domain_size_current/=2;
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
    use crate::hasher::Sha256_;
    #[test]
    pub fn test_(){
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fq> = coeff_u64.iter().map(|x| Fq::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fq> = DenseUVPolynomial::from_coefficients_vec(coeffs);

        let fri_config = FriConfig { num_query: 4, blow_up_factor: 2, last_polynomial_degree: 0 };

        let fri_proof = generate_fri_proof::<Fq, Sha256_<Fq>>(poly, fri_config.clone());
        
        assert!(verify_fri_proof(fri_config, (coeff_u64.len()-1) as u32, fri_proof))
    }
}