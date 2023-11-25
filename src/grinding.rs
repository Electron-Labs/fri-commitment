use sha3::{Digest, Keccak256};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
/* 

refereces: https://eprint.iacr.org/2021/582.pdf (ethstark)
https://github.com/starkware-libs/stone-prover/blob/main/src/starkware/channel/proof_of_work.h (Starkware stone prover)

*/ 


// Constant MAGIC: A unique prefix used in the hash computation.
const MAGIC: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];


// Validates whether a given nonce meets the criteria for a specific seed and difficulty level.
pub fn validate_nonce(seed_data: &[u8; 32], trial_nonce: u64, pow_bits: u8) -> bool {
    let computed_hash = hash(seed_data, pow_bits);
    let threshold = 1 << (64 - pow_bits);
    check_nonce_validity(&computed_hash, trial_nonce, threshold)
}

// Attempts to find a valid nonce that satisfies the grinding criteria for a given seed and difficulty level.
pub fn find_valid_nonce(seed_data: &[u8; 32], difficulty_level: u8) -> Option<u64> {
    let computed_hash = hash(seed_data, difficulty_level);
    let threshold = 1 << (64 - difficulty_level);
    (0..u64::MAX).into_par_iter().find_any(|&test_nonce| {
        check_nonce_validity(&computed_hash, test_nonce, threshold)
    })
}

// Internal function to check if a given nonce and hash combination is valid against the specified threshold.
fn check_nonce_validity(computed_hash: &[u8; 32], test_nonce: u64, threshold: u64) -> bool {
    let mut combined_data = [0; 40];
    combined_data[..32].copy_from_slice(computed_hash);
    combined_data[32..].copy_from_slice(&test_nonce.to_be_bytes());

    let result_digest = Keccak256::digest(combined_data);

    let leading_data = u64::from_be_bytes(result_digest[..8].try_into().unwrap());
    leading_data < threshold
}


// Generates a hash from the provided seed data and difficulty level, using the Keccak256 algorithm.
fn hash(seed_data: &[u8; 32], pow_bits: u8) -> [u8; 32] {
    let mut hash_input = [0u8; 41];
    hash_input[0..8].copy_from_slice(&MAGIC);
    hash_input[8..40].copy_from_slice(seed_data);
    hash_input[40] = pow_bits;
    let result_digest = Keccak256::digest(hash_input);
    result_digest[..32].try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::validate_nonce;
    use super::find_valid_nonce;

    #[test]
    fn test_valid_nonce_generation_pow_9() {
        let seed: [u8; 32] = [
            174, 187, 26, 134, 6, 43, 222, 151, 140, 48, 52, 67, 69, 181, 177, 165, 111, 222, 148,
            92, 130, 241, 171, 2, 62, 34, 95, 159, 37, 116, 155, 217,
        ];
        let pow_bits:u8 = 9;
        let nonce = find_valid_nonce(&seed, pow_bits).unwrap();

        assert!(validate_nonce(&seed, nonce, pow_bits));
    }  

    #[test]
    fn test_valid_nonce_generation_pow_10() {
        let seed: [u8; 32] = [
            // Unique seed for this test case
            12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 
            34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34, 56, 78, 90, 12, 34
        ];
        let pow_bits: u8 = 10;
        let nonce = find_valid_nonce(&seed, pow_bits).unwrap();

        assert!(validate_nonce(&seed, nonce, pow_bits));
    }  

    #[test]
    fn test_valid_nonce_generation_pow_19() {
        let seed: [u8; 32] = [
            // Another unique seed
            21, 43, 65, 87, 21, 43, 65, 87, 21, 43, 65, 87, 21, 43, 65, 87, 
            21, 43, 65, 87, 21, 43, 65, 87, 21, 43, 65, 87, 21, 43, 65, 87
        ];
        let pow_bits: u8 = 19;
        let nonce = find_valid_nonce(&seed, pow_bits).unwrap();

        assert!(validate_nonce(&seed, nonce, pow_bits));
    }

    #[test]
    fn test_valid_nonce_generation_pow_20() {
        let seed: [u8; 32] = [
            // Different seed
            98, 76, 54, 32, 10, 98, 76, 54, 32, 10, 98, 76, 54, 32, 10, 98,
            76, 54, 32, 10, 98, 76, 54, 32, 10, 98, 76, 54, 32, 10, 98, 76
        ];
        let pow_bits: u8 = 20;
        let nonce = find_valid_nonce(&seed, pow_bits).unwrap();

        assert!(validate_nonce(&seed, nonce, pow_bits));
    }

    #[test]
    fn test_valid_nonce_generation_pow_33() {
        let seed: [u8; 32] = [
            // Yet another unique seed
            11, 22, 33, 44, 55, 66, 77, 88, 99, 11, 22, 33, 44, 55, 66, 77,
            88, 99, 11, 22, 33, 44, 55, 66, 77, 88, 99, 11, 22, 33, 44, 55
        ];
        let pow_bits: u8 = 33;
        let nonce = find_valid_nonce(&seed, pow_bits).unwrap();

        assert!(validate_nonce(&seed, nonce, pow_bits));
    }

}

