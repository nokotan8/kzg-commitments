use crate::poly_commit::PolyCommit;
use crate::kzg10::KZG10;
use ark_ff::{AdditiveGroup, UniformRand, Field};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::{rand::Rng, test_rng};
use ark_bls12_381::{Bls12_381, Fr};

pub fn test() {
    let mut rng = test_rng();
    rng.r#gen::<i32>();
    let mut kzg = KZG10::<Bls12_381>::new();
    let (pk, _sk) = kzg.setup(16);
    
    let mut polynomials: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..1 {
        polynomials.push(DensePolynomial::<Fr>::rand(16, &mut rng));
    }
    let mut commitments = vec![];
    for poly in polynomials.clone() {
        commitments.push(kzg.commit(&pk, &DensePolynomial::from_coefficients_slice(&poly)));
    }

    let mut points: Vec<Fr> = vec![];
    for _i in 0..1 {
        // points.push(Fr::rand(&mut rng));
        points.push(Fr::ONE);
    }
    let values: Vec<Fr> = polynomials.clone().into_iter().map(|poly| points.clone().into_iter().map(move |point| poly.evaluate(&point))).flatten().collect();
    let proofs = kzg.open(&pk, &polynomials, &points, &values);
    println!("{}", kzg.verify(&commitments, &pk, &proofs, &points, &values).to_string());
}