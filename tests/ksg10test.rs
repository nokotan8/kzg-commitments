use kzg_commitments::poly_commit::PolyCommit;
use kzg_commitments::kzg10::KZG10;
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{rand::Rng, test_rng};
use ark_bls12_381::{Bls12_381, Fr};

#[test]
pub fn test() {
    let mut rng = test_rng();
    rng.r#gen::<i32>();

    let t = 8;
    
    let mut poly: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..t {
        poly.push(DensePolynomial::<Fr>::rand(16, &mut rng));
    }

    let mut poly_: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..t {
        poly_.push(DensePolynomial::<Fr>::rand(16, &mut rng));
    }

    let mut z: Vec<Fr> = vec![];
    for _ in 0..t {
        z.push(Fr::rand(&mut rng));
    }

    let mut z_: Vec<Fr> = vec![];
    for _ in 0..t {
        z_.push(Fr::rand(&mut rng));
    }

    let mut kzg = KZG10::<Bls12_381>::new();

    let (pk, _) = kzg.setup(128);

    let c = kzg.commit(&pk, &poly);
    let c_ = kzg.commit(&pk, &poly_);

    let v = kzg.evaluate(&poly, &z);

    let p = kzg.open(&pk, &poly, &z, &v, ());

    let b = KZG10::verify(&c, &pk, &p, &z, &v);
    assert_eq!(b, true);
    
    let b_ = KZG10::verify(&c_, &pk, &p, &z, &v);
    assert_eq!(b_, false);

    let b_ = KZG10::verify(&c, &pk, &p, &z_, &v);
    assert_eq!(b_, false);
}
