use ark_ff::PrimeField;
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};
use merlin::Transcript;

use crate::{hashing::hasher::Hasher_, merkle_tree::merkle::merkle_path_verify, fiat_shamir::fiat_shamir::TranscriptProtocol};

use super::types::{FRIProof, FriConfig};

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
