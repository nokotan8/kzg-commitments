use kzg_commitments::poly_commit::PolyCommit;
use ark_ff::UniformRand;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{rand::Rng, test_rng};
use ark_bls12_381::{Bls12_381, Fr};

use kzg_commitments::djba21::{DJBA21, DJBA21_PK};

fn main() {
    let mut rng = test_rng();
    rng.r#gen::<i32>();

    // let t = 128;
    // let d = 256;
    let t = 256;
    let d = 512;
    // let t = 1024;
    // let d = 2048;
    

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


    use std::time::Instant;
    let ver_param = (Fr::rand(&mut rng), Fr::rand(&mut rng));


    let mut djb = DJBA21::<Bls12_381>::new();

    let (pk, _) = djb.setup(d);

    let now = Instant::now();
    let c = djb.commit(&pk, &poly);
    println!("Commit takes: {:?}", now.elapsed());
    let c_ = djb.commit(&pk, &poly_);

    let now = Instant::now();
    let v = djb.evaluate(&poly, &z);
    println!("Evaluation takes: {:?}", now.elapsed());

    let now = Instant::now();
    let p = djb.open(&pk, &poly, &z, &v, &ver_param);
    println!("Opening takes: {:?}", now.elapsed());

    let now = Instant::now();
    let b = DJBA21::verify(&c, &pk, &p, &z, &v, &ver_param);
    assert_eq!(b, true);
    println!("Verify takes: {:?}", now.elapsed());
    
    let b_ = DJBA21::verify(&c_, &pk, &p, &z, &v, &ver_param);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p, &z_, &v, &ver_param);
    assert_eq!(b_, false);

}
