mod util;

use crate::util::{benchmark_poly_commit_with_curve, point_generator};
use criterion::{criterion_group, criterion_main};
use criterion::Criterion;
use kzg_commitments::djba21::DJBA21;
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::Bls12_381;
use ark_bls12_377::Bls12_377;
use ark_bn254::Bn254;
use ark_ec::bls12::Bls12;
use ark_std::test_rng;

fn b_djba21_bls12381(c: &mut Criterion) {
    fn verifier_init(_: usize) -> <DJBA21<Bls12<ark_bls12_381::Config>> as PolyCommit<Bls12_381>>::VerifierParams {
        let v = point_generator::<Bls12_381>(2, &mut test_rng());
        (v[0], v[1])
    }

    benchmark_poly_commit_with_curve::<Bls12_381, DJBA21<Bls12_381>>(
        c, 
        "djba21", 
        "bls12381", 
        &DJBA21::<Bls12_381>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        1024
    );
}

fn b_djba21_bls12377(c: &mut Criterion) {
    fn verifier_init(_: usize) -> <DJBA21<Bls12<ark_bls12_377::Config>> as PolyCommit<Bls12_377>>::VerifierParams {
        let v = point_generator::<Bls12_377>(2, &mut test_rng());
        (v[0], v[1])
    }

    benchmark_poly_commit_with_curve::<Bls12_377, DJBA21<Bls12_377>>(
        c, 
        "djba21", 
        "bls12377", 
        &DJBA21::<Bls12_377>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        1024
    );
}

fn b_djba21_bn254(c: &mut Criterion) {
    fn verifier_init(_: usize) -> <DJBA21<Bn254> as PolyCommit<Bn254>>::VerifierParams {
        let v = point_generator::<Bn254>(2, &mut test_rng());
        (v[0], v[1])
    }

    benchmark_poly_commit_with_curve::<Bn254, DJBA21<Bn254>>(
        c, 
        "djba21", 
        "bn254", 
        &DJBA21::<Bn254>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        1024
    );
}

criterion_group!(benches, b_djba21_bls12381, b_djba21_bls12377, b_djba21_bn254);
criterion_main!(benches);
