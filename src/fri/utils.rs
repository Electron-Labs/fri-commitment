use super::types::FriConfig;

/// Validates whether FRI config is valid
pub fn validate_fri_config (fri_config: &FriConfig, poly_degree: u32) -> bool {
    // Smallest possible array in FRI construction: blow_up * (last_poly_degree+1)
    // for merkle proof gen the smallest array utilised would be :
    // (blow_up * (last_poly_degree+1) * 2**(level_reductions_bits[level_reductions_bits.len()-1]))/2**(level_reductions_bits[level_reductions_bits.len()-1]
    assert!(fri_config.blow_up_factor * (fri_config.last_polynomial_degree+1) >= 1<<(fri_config.merkle_cap_bits+1), "Invalid FRI params (merkle cap)");

    // Verifies the reductions dont leave the array greater than last_polynomial_degree
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