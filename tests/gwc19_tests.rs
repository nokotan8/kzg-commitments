mod util;

use ark_bls12_381::Bls12_381;
use ark_ff::UniformRand;
use ark_std::test_rng;
use kzg_commitments::gwc19::{GWC19, GWC_PK};
use kzg_commitments::poly_commit::PolyCommit;
use util::{point_generator, poly_generator};

fn gwc19_helper(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let mut rng = test_rng();
    
    let poly = poly_generator(poly_count, poly_deg, &mut rng);

    let z = point_generator(point_count, &mut rng);
    
    let ver_params = point_generator(poly_count, &mut rng);

    let mut kzg = GWC19::<Bls12_381>::new();

    let (pk, _) = kzg.setup(poly_deg);

    let c = kzg.commit(&pk, &poly);

    let v = kzg.evaluate(&poly, &z);

    let p = kzg.open(&pk, &poly, &z, &v, &ver_params);

    GWC19::verify(&c, &pk, &p, &z, &v, &ver_params)
}

#[test]
fn gwc19_test() -> Result<(), ()> {
    let poly_deg_vals = [8, 16];
    let poly_count_vals = [1, 2, 4, 8, 16, 32];

    for &poly_count in &poly_count_vals {
        for &poly_deg in &poly_deg_vals {
            if !gwc19_helper(poly_count, poly_deg, poly_count) {
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
pub fn basic_gwc19_test() {
    let mut rng = test_rng();

    let t = 8;
    let d = t;
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

    let (pk, _) = kzg.setup(max_deg);
    let pk_ = GWC_PK::<Bls12_381> {
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
