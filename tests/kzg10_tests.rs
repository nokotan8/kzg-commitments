// use kzg_commitments::kzg_helpers::kzg10;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::test_rng;
use kzg_commitments::kzg10::{KZG10, KzgPK};
use kzg_commitments::poly_commit::PolyCommit;
use ark_std::rand::Rng;

fn poly_generator(poly_count: usize, poly_deg: usize, rng: &mut impl Rng) -> Vec<DensePolynomial<Fr>> {
    let mut poly = vec![];
    for _ in 0..poly_count {
        poly.push(DensePolynomial::<Fr>::rand(poly_deg, rng));
    }
    poly
}

fn point_generator(point_count: usize, rng: &mut impl Rng) -> Vec<Fr> {
    let mut z: Vec<Fr> = vec![];
    for _ in 0..point_count {
        z.push(Fr::rand(rng));
    }
    z
}

fn kzg10_helper(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let mut rng = test_rng();
    
    let poly = poly_generator(poly_count, poly_deg, &mut rng);

    let z = point_generator(point_count, &mut rng);

    let mut kzg = KZG10::<Bls12_381>::new();

    let (pk, _) = kzg.setup(poly_deg);

    let c = kzg.commit(&pk, &poly);

    let v = kzg.evaluate(&poly, &z);

    let p = kzg.open(&pk, &poly, &z, &v, ());

    KZG10::verify(&c, &pk, &p, &z, &v)
}

#[test]
fn kzg10_test() -> Result<(), ()> {
    let poly_deg_vals = [8, 16];
    let poly_count_vals = [1, 2, 4, 8];
    let point_count_vals = [1, 2, 4, 8];

    for &poly_count in &poly_count_vals {
        for &poly_deg in &poly_deg_vals {
            for &point_count in &point_count_vals {
                if !kzg10_helper(poly_count, poly_deg, point_count) {
                    println!(
                        "params: polys: {}, deg: {}, points: {}",
                        poly_count, poly_deg, point_count
                    );
                    return Err(());
                }
            }
        }
    }

    return Ok(());
}

#[test]
pub fn test() {
    let mut rng = test_rng();

    let t = 10;
    let d = 10;
    let max_deg = 128;
    
    let poly = poly_generator(t, d, &mut rng);
    let poly_ = poly_generator(t, d, &mut rng);
    
    let z = point_generator(t, &mut rng);
    let z_ = point_generator(t, &mut rng);
    
    let mut kzg = KZG10::<Bls12_381>::new();

    type G1 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1;
    type G2 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2;
    
    let (pk, _) = kzg.setup(max_deg);
    let pk_ = KzgPK::<Bls12_381> {
        g1_vec: vec![G1::rand(&mut rng); t],
        g2_1: G2::rand(&mut rng),
        g2_x: G2::rand(&mut rng)
    };

    let c = kzg.commit(&pk, &poly);
    let c_ = kzg.commit(&pk, &poly_);

    let v = kzg.evaluate(&poly, &z);
    let v_ = kzg.evaluate(&poly_, &z);

    let p = kzg.open(&pk, &poly, &z, &v, ());
    let p_ = kzg.open(&pk, &poly, &z_, &v, ());

    let b = KZG10::verify(&c, &pk, &p, &z, &v);
    assert_eq!(b, true);
    
    let b_ = KZG10::verify(&c_, &pk, &p, &z, &v);
    assert_eq!(b_, false);
    
    let b_ = KZG10::verify(&c, &pk_, &p, &z, &v);
    assert_eq!(b_, false);

    let b_ = KZG10::verify(&c, &pk, &p_, &z, &v);
    assert_eq!(b_, false);

    let b_ = KZG10::verify(&c, &pk, &p, &z_, &v);
    assert_eq!(b_, false);

    let b_ = KZG10::verify(&c, &pk, &p, &z, &v_);
    assert_eq!(b_, false);
}