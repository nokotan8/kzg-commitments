use kzg_commitments::poly_commit::PolyCommit;
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{rand::Rng, test_rng};
use ark_bls12_381::{Bls12_381, Fr};

use kzg_commitments::djba21::{DJBA21, DJBA21_PK};

fn main() {
    let mut rng = test_rng();
    rng.r#gen::<i32>();

    let t = 128;
    let d = 128;
    

    let mut poly: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..t {
        poly.push(DensePolynomial::<Fr>::rand(d, &mut rng));
    }
    
    let mut poly_: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..t {
        poly_.push(DensePolynomial::<Fr>::rand(d, &mut rng));
    }

    let mut z_: Vec<Fr> = vec![];
    for _ in 0..t {
        z_.push(Fr::rand(&mut rng));
    }

    let mut z: Vec<Fr> = vec![];
    for _ in 0..t {
        z.push(Fr::rand(&mut rng));
    }


    let ver_param = (Fr::rand(&mut rng), Fr::rand(&mut rng));


    let mut djb = DJBA21::<Bls12_381>::new();

    let (pk, _) = djb.setup(d);

    let c = djb.commit(&pk, &poly);
    let c_ = djb.commit(&pk, &poly_);

    let v = djb.evaluate(&poly, &z);

    let p = djb.open(&pk, &poly, &z, &v, ver_param);

    let b = DJBA21::verify(&c, &pk, &p, &z, &v, ver_param);
    assert_eq!(b, true);
    
    let b_ = DJBA21::verify(&c_, &pk, &p, &z, &v, ver_param);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p, &z_, &v, ver_param);
    assert_eq!(b_, false);

}
