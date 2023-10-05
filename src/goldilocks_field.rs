// use ark_ff::{Field, PrimeField, Zero, BigInt, BigInteger};
// use ark_ff::FpConfig;
// use ark_std::{rand::Rng, test_rng};

// // Define the Goldilocks prime
// const GOLDILOCKS_MODULUS: &'static [u64] = &[
//     0xffffffffff58ab00,
// ];

// pub struct GoldilocksConfig {}

// const N: usize = 1;

// impl FpConfig<N> for GoldilocksConfig {
//     const MODULUS: ark_ff::BigInt<N> = ark_ff::BigInt::from(18446744069414584321 as u64);

//     const GENERATOR: ark_ff::Fp<Self, N> = ark_ff::Fp::from(7 as u64);

//     const ZERO: ark_ff::Fp<Self, 1> = ark_ff::Fp::from(0);

//     const ONE: ark_ff::Fp<Self, N> = ark_ff::Fp::from(1);

//     const TWO_ADICITY: u32 = 32;

//     const TWO_ADIC_ROOT_OF_UNITY: ark_ff::Fp<Self, N> = ark_ff::Fp::from(0); // TODO

//     const SQRT_PRECOMP: Option<ark_ff::SqrtPrecomputation<ark_ff::Fp<Self, N>>> = None;

//     fn add_assign(a: &mut ark_ff::Fp<Self, N>, b: &ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn sub_assign(a: &mut ark_ff::Fp<Self, N>, b: &ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn double_in_place(a: &mut ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn neg_in_place(a: &mut ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn mul_assign(a: &mut ark_ff::Fp<Self, N>, b: &ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn sum_of_products<const T: usize>(a: &[ark_ff::Fp<Self, N>; T], b: &[ark_ff::Fp<Self, N>; T]) -> ark_ff::Fp<Self, N> {
//         todo!()
//     }

//     fn square_in_place(a: &mut ark_ff::Fp<Self, N>) {
//         todo!()
//     }

//     fn inverse(a: &ark_ff::Fp<Self, N>) -> Option<ark_ff::Fp<Self, N>> {
//         todo!()
//     }

//     fn from_bigint(other: ark_ff::BigInt<N>) -> Option<ark_ff::Fp<Self, N>> {
//         todo!()
//     }

//     fn into_bigint(other: ark_ff::Fp<Self, N>) -> ark_ff::BigInt<N> {
//         todo!()
//     }

//     const SMALL_SUBGROUP_BASE: Option<u32> = None;

//     const SMALL_SUBGROUP_BASE_ADICITY: Option<u32> = None;

//     const LARGE_SUBGROUP_ROOT_OF_UNITY: Option<ark_ff::Fp<Self, N>> = None;
// }


// // impl FpParameters for GoldilocksParameters {
// //     type BigInt = ark_std::biginteger::BigInteger256;

// //     // Returns the modulus of the field
// //     fn modulus() -> Self::BigInt {
// //         Self::BigInt::from_limbs(GOLDILOCKS_MODULUS)
// //     }

// //     // Most of the other parameters can be left default for basic operations.
// //     // You might need to fill these in if you want more advanced features.
// //     fn number_of_modulus_bits() -> u32 {
// //         255
// //     }
// //     fn capacity() -> u32 {
// //         Self::number_of_modulus_bits() - 1
// //     }
// //     fn t() -> Self::BigInt {
// //         unimplemented!() // Fill if necessary
// //     }
// //     fn t_minus_1_over_2() -> Self::BigInt {
// //         unimplemented!() // Fill if necessary
// //     }
// //     fn multiplicative_generator() -> Self::BigInt {
// //         unimplemented!() // Fill if necessary
// //     }
// //     fn root_of_unity() -> Self::BigInt {
// //         unimplemented!() // Fill if necessary
// //     }
// //     fn modulus_minus_one_div_two() -> Self::BigInt {
// //         (Self::modulus() - Self::BigInt::from(1u64)) / Self::BigInt::from(2u64)
// //     }
// // }

// // Define the GoldilocksField using the parameters
// pub type GoldilocksField = ark_ff::Fp256<GoldilocksParameters>;

// fn main() {
//     let mut rng = test_rng();

//     let a: GoldilocksField = rng.gen();
//     let b: GoldilocksField = rng.gen();

//     let sum = a + b;

//     println!("a = {:?}", a);
//     println!("b = {:?}", b);
//     println!("a + b = {:?}", sum);
// }

