use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;

pub fn poly_generator(poly_count: usize, poly_deg: usize, rng: &mut impl Rng) -> Vec<DensePolynomial<Fr>> {
    let mut poly = vec![];
    for _ in 0..poly_count {
        poly.push(DensePolynomial::<Fr>::rand(poly_deg, rng));
    }
    poly
}

pub fn point_generator(point_count: usize, rng: &mut impl Rng) -> Vec<Fr> {
    let mut z: Vec<Fr> = vec![];
    for _ in 0..point_count {
        z.push(Fr::rand(rng));
    }
    z
}