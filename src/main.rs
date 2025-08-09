use ark_bls12_381::Bls12_381;
use ark_ff::{Field, UniformRand};
use ark_std::test_rng;
use kzg_commitments::gwc19::{GWC19, GwcPK};
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::Fr;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;
use std::ops::Mul;

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

fn basic_gwc19_test() {
    let mut rng = test_rng();

    let t = 4;
    let d = 16;
    let max_deg = 128;

    let poly = poly_generator(t, d, &mut rng);
    let poly_ = poly_generator(t, d, &mut rng);

    let z = point_generator(t, &mut rng);
    let z_ = point_generator(t, &mut rng);

    let ver_params = point_generator(t, &mut rng);
    let ver_params_ = point_generator(t, &mut rng);

    let mut kzg = GWC19::<Bls12_381>::new();

    
    type G1 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1;
    type G2 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2;
    
    let g = G1::rand(&mut rng);
    assert_eq!(g, g.mul(Fr::ONE));

    let (pk, _) = kzg.setup(max_deg);
    let pk_ = GwcPK::<Bls12_381> {
        g1_vec: vec![G1::rand(&mut rng); t],
        g2_1: G2::rand(&mut rng),
        g2_x: G2::rand(&mut rng),
    };

    let c = kzg.commit(&pk, &poly);
    let c_ = kzg.commit(&pk, &poly_);

    let v = kzg.evaluate(&poly, &z);
    let v_ = kzg.evaluate(&poly_, &z);

    let p = kzg.open(&pk, &poly, &z, &v, &ver_params);
    let p_ = kzg.open(&pk, &poly, &z_, &v, &ver_params);

    let mut b;
    
    b = GWC19::verify(&c, &pk, &p, &z, &v, &ver_params);
    assert_eq!(b, true);

    b = GWC19::verify(&c_, &pk, &p, &z, &v, &ver_params);
    assert_eq!(b, false);
    
    b = GWC19::verify(&c, &pk_, &p, &z, &v, &ver_params);
    assert_eq!(b, false);
    
    b = GWC19::verify(&c, &pk, &p_, &z, &v, &ver_params);
    assert_eq!(b, false);
    
    b = GWC19::verify(&c, &pk, &p, &z_, &v, &ver_params);
    assert_eq!(b, false);
    
    b = GWC19::verify(&c, &pk, &p, &z, &v_, &ver_params);
    assert_eq!(b, false);
    
    b = GWC19::verify(&c, &pk, &p, &z, &v, &ver_params_);
    assert_eq!(b, false);
}

fn main() {
    basic_gwc19_test();
}
