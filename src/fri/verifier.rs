use ark_ff::PrimeField;
use ark_poly::{GeneralEvaluationDomain, EvaluationDomain};
use merlin::Transcript;

use crate::{hashing::hasher::Hasher_, merkle_tree::merkle::merkle_path_verify, fiat_shamir::fiat_shamir::TranscriptProtocol};

use super::types::{FRIProof, FriConfig};

// Interpolates the previous level (xi,yi) and uses verifier challenge to compute value at next level
pub fn calcualate_next_level_value<F: PrimeField + std::convert::From<i32>>(
    level_query_points: Vec<usize>,
    level_query_evaluations: Vec<F>,
    rando: F,
    eval_domain: GeneralEvaluationDomain<F>
) -> F {
    assert_eq!(level_query_points.len(), level_query_evaluations.len());
    // L(x) = ∑ (i=1-n) Yi ∏ (j=1-n, i≠j) (X-Xj)/(Xi-Xj)
    // C = ∏ (j=1-n) (X-Xj)
    // L(x) = ∑ (i=1-n) Yi * C/((X-Xi) * ∏(j=1-n, i≠j)(Xi-Xj))
    let mut next_level_val = F::ZERO;

    let c: F = level_query_points.clone().into_iter().map(|q| rando-eval_domain.element(q)).product();

    for i in 0..level_query_points.len(){
        let d = eval_domain.element(level_query_points[i]);
        let denom: F = level_query_points.clone()
            .iter()
            .enumerate()
            .filter(|(j,_q)| i != *j)
            .map(|(_j, q)| {d-eval_domain.element(*q)})
            .product();
        next_level_val += (level_query_evaluations[i]*c)/((rando-d)*denom);
    }

    next_level_val
}

pub fn verify_fri_proof<F: PrimeField + std::convert::From<i32>, H: Hasher_<F>> (fri_config: FriConfig, degree: u32, fri_proof: FRIProof<F,H>) -> bool {
    println!("--- Verifying FRI LDE check for degree {:?} ---", degree);

    let final_evaluations = fri_proof.final_evaluations;

    let final_evalutaion_degree = fri_config.last_polynomial_degree;

    let eval_proofs = fri_proof.query_eval_proofs;
    let level_roots = fri_proof.level_roots;

    let mut transcript = Transcript::new(b"new transcript");

    // Extract random verifier challenges from fiat-shamir
    let mut verifier_randoms = vec![];
    for root in level_roots.iter() {
        let merkle_root_cap_field:Vec<F> = root.iter().map(|r| H::hash_as_field(r.clone())).collect();
        transcript.observe_elements(b"merkle_root", &merkle_root_cap_field);
        let verifier_rand: F = transcript.get_challenge(b"alpha");
        verifier_randoms.push(verifier_rand);
    }

    // Extract queries from fiat-shamir 
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

    // [TODO] no need to calculate when we move to sending coeffs since no need of interpolation required
    let mut final_offset = F::GENERATOR;
    for exp in fri_config.level_reductions_bits.clone() {
        final_offset = final_offset.pow([exp as u64]);
    }

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
    for q_start in queries {
        // println!("Starting to verify query -- {:?}", i+1);
        println!("Starting to verify query -- {:?}", q_start);
        let mut domain_size_current = original_domain_size as usize;
        
        // Bring query to first half of domain
        let q_init = (q_start as usize)%(domain_size_current/2);

        // Contains value of element in next folded level for consistency check
        let mut next_level_value: F = F::one();

        let mut offset = F::GENERATOR;

        for l in 0..levels_to_iterate {
            let reduction = 1<<fri_config.level_reductions_bits[l];
            let q = q_init%domain_size_current;
            
            println!("Verifying query {:?} at level {:?}",q,l);

            // Extract evaluation proof for the query at the level l
            let eval_proof = eval_proofs[l].get(&q).unwrap();

            // Verify merkle proof asserting leaf belongs to the commited root
            assert!(merkle_path_verify::<F,H>(&eval_proof.merkle_proof)); 

            // Contains all evaluations of this level required corresponding to that query for evaluation of next value in the reduced polynomail evaluations
            // Evaluations will always be sorted in the order of their sorted queries
            let evaluations = eval_proof.merkle_proof.leaf.clone();

            if l !=0 {
                // check prev round to current round consistency
                // (q/reduction) -> maps the query index to the index in corresponding merkle leaf
                assert_eq!(next_level_value, evaluations[q/reduction], "Consistency check failed for query {:?} between levels {:?} and {:?}", q, l-1, l);
            }

            let query_addition_factor = domain_size_current/reduction;

            let mut level_query_set: Vec<usize> = Vec::new();

            for i in 0..(1<<fri_config.level_reductions_bits[l]) {
                let tmp = (q + i * query_addition_factor)%domain_size_current;
                level_query_set.push(tmp);
            }
            level_query_set.sort();

            let mut eval_domain_verifier: GeneralEvaluationDomain<F> = GeneralEvaluationDomain::new(domain_size_current).unwrap();
            eval_domain_verifier = eval_domain_verifier.get_coset(offset).expect("Error in getting coset");

            let verifier_rand = verifier_randoms[l];

            next_level_value = calcualate_next_level_value(level_query_set, evaluations, verifier_rand, eval_domain_verifier);;

            domain_size_current = domain_size_current>>fri_config.level_reductions_bits[l];
            offset = offset.pow([reduction as u64]);
        }
        let q_final = (q_start as usize)%(domain_size_current);
        assert_eq!(final_evaluations[q_final], next_level_value);
    }
    true
}
