mod util;

use crate::util::benchmark_poly_commit_with_curve;
use criterion::{criterion_group, criterion_main};
use criterion::Criterion;
use kzg_commitments::kzg10::KZG10;
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::Bls12_381;
use ark_bls12_377::Bls12_377;
use ark_bn254::Bn254;
use ark_std::test_rng;

fn b_kzg10_bls12381(c: &mut Criterion) {
    benchmark_poly_commit_with_curve::<Bls12_381, KZG10<Bls12_381>>(
        c, 
        "kzg10", 
        "bls12381", 
        &KZG10::<Bls12_381>::new, 
        &|_|(),
        &mut test_rng(),
        64,
        64
    );
}

fn b_kzg10_bls12377(c: &mut Criterion) {
    benchmark_poly_commit_with_curve::<Bls12_377, KZG10<Bls12_377>>(
        c, 
        "kzg10", 
        "bls12377", 
        &KZG10::<Bls12_377>::new, 
        &|_|(),
        &mut test_rng(),
        64,
        64
    );
}

fn b_kzg10_bn254(c: &mut Criterion) {
    benchmark_poly_commit_with_curve::<Bn254, KZG10<Bn254>>(
        c, 
        "kzg10", 
        "bn254", 
        &KZG10::<Bn254>::new, 
        &|_|(),
        &mut test_rng(),
        64,
        64
    );
}

criterion_group!(benches, b_kzg10_bls12381, b_kzg10_bls12377, b_kzg10_bn254);
criterion_main!(benches);
