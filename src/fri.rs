// FRI Low Degree Testing

// --- Generate Proof ---
// 1. Get a Polynomial
// 2. Get domain at degree * bp_factor
// 3. get array of evals at this point
// 4. Splittng
// 5. Mixing
// 4. Comitting
// 5. Give Merkle proofs for t queries at the end? 
// if queried at f(w):
// give proof for f0(w) and f0(-w)
// give proof for f1(w^2) and f1(-w^2)
// give proof for f2(w^3) and f2(-w^3)
// ... so on

use std::collections::HashMap;

use ark_ff::Fp256;
// --- Verify FRI LDT ---
// 1. Merkle Proof verfcn for points at each query
// 2. round by round consistency checks for each round
use ark_poly::{polynomial::univariate::DensePolynomial, EvaluationDomain, Polynomial};

use ark_bn254::Fr;
use ark_poly::GeneralEvaluationDomain;
use rs_merkle::{MerkleTree, MerkleProof};
// use rs_merkle::algorithms::Sha256;
use rs_merkle::algorithms::Sha256;
use ark_poly::DenseUVPolynomial;
use ark_std::{rand::Rng, UniformRand, ops::{Mul, Add}};
use ark_ff::Field;

const bp_factor: usize = 2;
const t_queries: [usize; 4] = [1,2,5,7];
// const t_queries: [usize; 1] = [1];



pub fn low_degree_extension_proof(poly_org: DensePolynomial<Fr>) {
    let mut rng = ark_std::test_rng();

    let mut poly_x: Vec<DensePolynomial<Fr>>  = Vec::new();

    let degree = poly_org.coeffs.len(); 
    
    poly_x.push(poly_org.clone());
    
    let mut degree_now = degree; // basically coeffs called degree here

    let mut merkle_trees = Vec::new();

    let mut merkle_tree_roots: Vec<[u8; 32]> = Vec::new();

    let mut merkle_proofs: Vec<Vec<MerkleProof<Sha256>>> = Vec::new();

    let mut verifier_rands = Vec::<Fr>::new();

    let mut curr_poly_idx = 0;

    let mut query_evaluations: Vec<Vec<Fr>> = vec![];

    let mut final_evaluation: Vec<Fr> = vec![];
    let mut queries: Vec<usize> = t_queries.clone().into();

    let mut round: u32 = 1;

    while true {
        println!("-- level {:?} ---", curr_poly_idx);
        println!("query {:?}", queries);
        

        let poly = poly_x[curr_poly_idx].clone();
        println!("poly_coeffs {:?}", poly.coeffs());
        println!("degree {:?}", degree_now);

        let mut domain_size = degree_now * bp_factor;

        let eval_domain: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(domain_size).unwrap();

        let evaluations_1: Vec<Fr> = eval_domain.elements().map(|d: Fr| return poly.evaluate(&d)).collect();

        if degree_now == 1 {
            assert_eq!(poly.coeffs.len(), 1);
            final_evaluation = evaluations_1;
            break;
        }

        domain_size = evaluations_1.len();

        println!("domain size {:?}", evaluations_1.len());

        let mut ev1_bytes: Vec<Vec<u8>> = evaluations_1.iter().map(|ev| 
            ev.0.0.iter().flat_map(|e_64| e_64.to_le_bytes()).collect()
        ).collect();

        let ev1_bytes_: Vec<[u8;32]> = ev1_bytes.iter().map(|x| x.clone().try_into().unwrap()).collect();

        
        let mk1 = MerkleTree::<Sha256>::from_leaves(&ev1_bytes_);
        // merkle_roots.push(mk1.root().unwrap());
        merkle_trees.push(mk1.clone());

        merkle_tree_roots.push(mk1.root().unwrap());

        let mut proofs_this_level = Vec::<MerkleProof<Sha256>>::new();

        let mut this_level_query_evals = Vec::<Fr>::new();

        for i in 0..queries.len() {
            let pos_idx = queries[i];
            let neg_idx = (queries[i]+domain_size/2)%domain_size;
            this_level_query_evals.push(evaluations_1[pos_idx]);
            if(i==0) {
                println!("proof-{:?}, {:?}, {:?}, {:?}", mk1.root().unwrap(), pos_idx, mk1.leaves().unwrap()[pos_idx], mk1.leaves_len());
                let mk1_proof = mk1.proof(&[pos_idx]);
                assert!(mk1_proof.verify(
                   mk1.root().unwrap(), &[pos_idx], &[mk1.leaves().unwrap()[pos_idx]], mk1.leaves_len()));
            }
            
            proofs_this_level.push(mk1.proof(&[pos_idx]));
            
            this_level_query_evals.push(evaluations_1[neg_idx]);
            proofs_this_level.push(mk1.proof(&[neg_idx]));
        }

        query_evaluations.push(this_level_query_evals);

        assert_eq!(proofs_this_level.len() , queries.len()*2);

        merkle_proofs.push(proofs_this_level);


        let ver_rand_1 = Fr::rand(&mut rng);

        verifier_rands.push(ver_rand_1);

        let mut mixed_coeffs= Vec::<Fr>::new();
        let mut even_coeffs: Vec<Fr> = vec![];
        let mut odd_coeffs: Vec<Fr> = vec![];
        for i in 0..poly.coeffs.len() {
        // for i in (0..poly.coeffs.len()).step_by(2) {
            // if poly.coeffs.len() == i+1 {
            //     mixed_coeffs.push(poly.coeffs[i])
            // }else {
            //     mixed_coeffs.push(poly.coeffs[i] + (ver_rand_1 * poly.coeffs[i+1]));
            // }
            if i%2==0 {
                even_coeffs.push(poly.coeffs[i]);
            } else {
                odd_coeffs.push(poly.coeffs[i]);
            }
        }
        let even_ploy: DensePolynomial<Fr> = DenseUVPolynomial::from_coefficients_vec(even_coeffs);
        let odd_poly: DensePolynomial<Fr> = DensePolynomial::from_coefficients_vec(odd_coeffs);

        let mixed_poly_1 = even_ploy.add(odd_poly.mul(ver_rand_1));

        // let mixed_poly_1: DensePolynomial<Fr> = DenseUVPolynomial::from_coefficients_vec(mixed_coeffs);

        poly_x.push(mixed_poly_1.clone());

        curr_poly_idx += 1;

        degree_now/=2; //floor here
        println!("domain_br {:?}",domain_size);
        for i in 0..queries.len() {
            queries[i] = (queries[i])%(domain_size/2);
        }
        queries.sort();
        queries.dedup();

        round += 1;
    }
    println!("final evaluation: {:?}", final_evaluation);

    // --- Verification ---
    
    // check the number of levels
    let levels = merkle_proofs.len(); // -> log2(k)
    print!("levels {:?}", levels);
    let correct_levels = (degree as f32).log2() as usize;
    assert_eq!(levels, correct_levels);


    // verify level by level
    queries = t_queries.clone().into();
    let last_codeword_len = final_evaluation.len();
    assert_eq!(last_codeword_len, bp_factor);
    let mut verify_domain_size = degree * bp_factor;

    let mut level_evals: Vec<HashMap<usize, Fr>> = Vec::new();

    for i in 0..levels {
        println!("levels --- {i}");
        assert_eq!(queries.len()*2, merkle_proofs[i].len());
        let rand = verifier_rands[i];
        println!("round -- {i}, alpha -- {:?}", rand);
        let mut val_map = HashMap::<usize, Fr>::new();
        for j in (0..merkle_proofs[i].len()).step_by(2) {
            println!("j {:?}", j);
            // let proof = &merkle_proofs[i][j];


            let pos_idx = queries[j/2];
            let neg_idx = (queries[j/2]+verify_domain_size/2)%verify_domain_size;
            let eval_pos = query_evaluations[i][j];
            let eval_pos_bytes: Vec<u8> = eval_pos.0.0.iter().flat_map(|e_64| e_64.to_le_bytes()).collect();
            let eval_pos_bytes: [u8; 32] = eval_pos_bytes.try_into().unwrap();
            if(j==0){
                println!("verify -- {:?} {:?} {:?} {:?}",merkle_tree_roots[i], pos_idx, eval_pos_bytes, verify_domain_size);
            }
            assert!(merkle_proofs[i][j].verify(merkle_tree_roots[i], &[pos_idx], &[eval_pos_bytes], verify_domain_size));

            let eval_neg = query_evaluations[i][j+1];
            let eval_neg_bytes: Vec<u8> = eval_neg.0.0.iter().flat_map(|e_64| e_64.to_le_bytes()).collect();
            let eval_neg_bytes: [u8; 32] = eval_neg_bytes.try_into().unwrap();

            assert!(merkle_proofs[i][j+1].verify(merkle_tree_roots[i], &[neg_idx], &[eval_neg_bytes], verify_domain_size));

            let eval_domain_verifier: GeneralEvaluationDomain<Fr> = GeneralEvaluationDomain::new(verify_domain_size).unwrap();
            let denom = eval_domain_verifier.element(pos_idx) * Fr::from(2);
            // println!("eval_dom_elems {:?}", eval_domain_elements);
            // let denom = eval_domain_verifier.element(pos_idx)*Fr::from(2);
            println!("denom {:?}", denom);
            let next_level_idx = (pos_idx)%(verify_domain_size/2);
            println!("next_level_idx {:?}", next_level_idx);
            let next_level_val = 
                (((eval_pos+eval_neg))/(Fr::from(2))) + (rand*((eval_pos-eval_neg)/denom));

            let inserted = val_map.insert(next_level_idx, next_level_val); 
            match inserted {
                Some(s) => {
                    // todo!()
                    assert_eq!(s, next_level_val);
                },
                None => (),
            };
            

            if i>0 {
                assert_eq!(level_evals[i-1].get(&pos_idx).unwrap(), &eval_pos);
            }
        }
        level_evals.push(val_map);
        verify_domain_size /= 2;
        for j in 0..queries.len() {
            queries[j] = (queries[j])%(verify_domain_size);
        }
        queries.sort();
        queries.dedup();
    }

}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    pub fn test_ (){
        //The coefficient of x^i is stored at location i in coeffs.
        let coeff_u64: Vec<i64> = vec![19, 56, 34, 48,43,37, 10, 10];
        let coeffs: Vec<Fr> = coeff_u64.iter().map(|x| Fr::from(x.clone())).collect();

        // 19 + 56x + 34x^2 + 48x^3 + 43x^4 + 37x^5 + 10x^6 + 10x^7
        let poly: DensePolynomial<Fr> = DenseUVPolynomial::from_coefficients_vec(coeffs);
        println!("polynomial {:?}", poly);
        low_degree_extension_proof(poly);
    }
}