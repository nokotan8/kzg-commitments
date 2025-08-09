mod util;

use crate::util::{benchmark_poly_commit_with_curve, point_generator};
use criterion::{criterion_group, criterion_main};
use criterion::Criterion;
use kzg_commitments::gwc19::GWC19;
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::Bls12_381;
use ark_bls12_377::Bls12_377;
use ark_ec::bls12::Bls12;
use ark_bn254::Bn254;
use ark_std::test_rng;

fn b_gwc19_bls12381(c: &mut Criterion) {
    fn verifier_init(t: usize) -> <GWC19<Bls12<ark_bls12_381::Config>> as PolyCommit<Bls12_381>>::VerifierParams {
        point_generator::<Bls12_381>(t, &mut test_rng())
    }

    benchmark_poly_commit_with_curve::<Bls12_381, GWC19<Bls12_381>>(
        c, 
        "gwc19", 
        "bls12381", 
        &GWC19::<Bls12_381>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        512
    );
}

fn b_gwc19_bls12377(c: &mut Criterion) {
    fn verifier_init(t: usize) -> <GWC19<Bls12<ark_bls12_377::Config>> as PolyCommit<Bls12_377>>::VerifierParams {
        point_generator::<Bls12_377>(t, &mut test_rng())
    }

    benchmark_poly_commit_with_curve::<Bls12_377, GWC19<Bls12_377>>(
        c, 
        "gwc19", 
        "bls12377", 
        &GWC19::<Bls12_377>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        512
    );
}

fn b_gwc19_bn254(c: &mut Criterion) {
    fn verifier_init(t: usize) -> <GWC19<Bn254> as PolyCommit<Bn254>>::VerifierParams {
        point_generator::<Bn254>(t, &mut test_rng())
    }

    benchmark_poly_commit_with_curve::<Bn254, GWC19<Bn254>>(
        c, 
        "gwc19", 
        "bn254", 
        &GWC19::<Bn254>::new, 
        &verifier_init,
        &mut test_rng(),
        256,
        512
    );
}

criterion_group!(benches, b_gwc19_bls12381, b_gwc19_bls12377, b_gwc19_bn254);
criterion_main!(benches);
