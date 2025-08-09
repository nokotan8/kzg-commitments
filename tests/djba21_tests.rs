mod util;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_std::test_rng;
use kzg_commitments::djba21::{DJBA21, DJBA21_PK};
use kzg_commitments::poly_commit::PolyCommit;
use util::{point_generator, poly_generator};

fn djba21_helper(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let mut rng = test_rng();
    
    let poly = poly_generator(poly_count, poly_deg, &mut rng);

    let z = point_generator(point_count, &mut rng);

    let ver_params = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    let mut djba = DJBA21::<Bls12_381>::new();

    let (pk, _) = djba.setup(poly_deg);

    let c = djba.commit(&pk, &poly);

    let v = djba.evaluate(&poly, &z);

    let p = djba.open(&pk, &poly, &z, &v, &ver_params);

    DJBA21::verify(&c, &pk, &p, &z, &v, &ver_params)
}

#[test]
fn djba21_test() -> Result<(), ()> {
    let poly_deg_vals = [8, 16];
    let poly_count_vals = [1, 2, 4, 8, 16, 32];

    for &poly_count in &poly_count_vals {
        for &poly_deg in &poly_deg_vals {
            if !djba21_helper(poly_count, poly_deg, poly_count) {
                println!(
                    "params: polys: {}, deg: {}, points: {}",
                    poly_count, poly_deg, poly_count
                );
                return Err(());
            }
        }
    }

    return Ok(());
}

#[test]
pub fn test() {
    let mut rng = test_rng();

    let t = 8;
    let d = 16;
    let max_deg = 128;
    
    let poly = poly_generator(t, d, &mut rng);
    let poly_ = poly_generator(t, d, &mut rng);
    
    let z = point_generator(t, &mut rng);
    let z_ = point_generator(t, &mut rng);

    let mut djba = DJBA21::<Bls12_381>::new();

    type G1 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G1;
    type G2 = <ark_ec::models::bls12::Bls12<ark_bls12_381::Config> as ark_ec::pairing::Pairing>::G2;
    
    let (pk, _) = djba.setup(max_deg);
    let pk_ = DJBA21_PK::<Bls12_381> {
        g1: vec![G1::rand(&mut rng); t],
        g2_one: G2::rand(&mut rng),
        g2_x: G2::rand(&mut rng)
    };

    let c = djba.commit(&pk, &poly);
    let c_ = djba.commit(&pk, &poly_);

    let v = djba.evaluate(&poly, &z);
    let v_ = djba.evaluate(&poly_, &z);

    let ver_params = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let ver_params_ = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    let p = djba.open(&pk, &poly, &z, &v, &ver_params);
    let p_ = djba.open(&pk, &poly, &z_, &v, &ver_params);

    let b = DJBA21::verify(&c, &pk, &p, &z, &v, &ver_params);
    assert_eq!(b, true);
    
    let b_ = DJBA21::verify(&c_, &pk, &p, &z, &v, &ver_params);
    assert_eq!(b_, false);
    
    let b_ = DJBA21::verify(&c, &pk_, &p, &z, &v, &ver_params);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p_, &z, &v, &ver_params);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p, &z_, &v, &ver_params);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p, &z, &v_, &ver_params);
    assert_eq!(b_, false);

    let b_ = DJBA21::verify(&c, &pk, &p, &z, &v, &ver_params_);
    assert_eq!(b_, false);
}
