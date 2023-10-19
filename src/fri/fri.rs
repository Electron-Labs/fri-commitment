

#[cfg(test)]
mod test {
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use crate::fri::types::FriConfig;
    use crate::fri::verifier::verify_fri_proof;
    use crate::{hashing::hasher::Sha256_, fri::prover::generate_fri_proof};
    use crate::fields::goldilocks_field::Fq;
    
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