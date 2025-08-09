mod util;

use crate::util::{benchmark_poly_commit_with_curve, point_generator};
use criterion::{criterion_group, criterion_main};
use criterion::Criterion;
use kzg_commitments::djba21::DJBA21;
use kzg_commitments::kzg10::KZG10;
use kzg_commitments::gwc19::GWC19;
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::Bls12_381;
use ark_bls12_377::Bls12_377;
use ark_bn254::Bn254;
use ark_std::test_rng;
use ark_ec::pairing::Pairing;

fn benchmark_kzg10<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    benchmark_poly_commit_with_curve::<E, KZG10<E>>(c, "kzg10", curve_name, &|_|(), &mut test_rng(), poly_deg, poly_count);
}

fn benchmark_gwc19<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    fn gwc19_verifier_init<E: Pairing>(t: usize) -> <GWC19<E> as PolyCommit<E>>::VerifierParams {
        point_generator::<E>(t, &mut test_rng())
    }
    benchmark_poly_commit_with_curve::<E, GWC19<E>>(c, "gwc19", curve_name, &gwc19_verifier_init::<E>, &mut test_rng(), poly_deg, poly_count);
}

fn benchmark_djba21<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    fn djba21_verifier_init<E: Pairing>(_t: usize) -> <DJBA21<E> as PolyCommit<E>>::VerifierParams {
        let v = point_generator::<E>(2, &mut test_rng());
        (v[0], v[1])
    }
    benchmark_poly_commit_with_curve::<E, DJBA21<E>>(c, "djba21", curve_name, &djba21_verifier_init::<E>, &mut test_rng(), poly_deg, poly_count);
}

fn benchmark(c: &mut Criterion) {
    let poly_deg = [8, 16, 32, 64, 128, 256];
    let poly_count = [
        (1, 100), (2, 100), (4, 100), (8, 100), 
        (16, 50), (32, 50), (64, 50), (128, 50), 
        (256, 25), (512, 25), (1024, 25)
    ];

    benchmark_kzg10::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count);
    benchmark_kzg10::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count);
    benchmark_kzg10::<Bn254>(c, "bn254", &poly_deg, &poly_count);

    benchmark_gwc19::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count);
    benchmark_gwc19::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count);
    benchmark_gwc19::<Bn254>(c, "bn254", &poly_deg, &poly_count);
    
    benchmark_djba21::<Bls12_381>(c, "bls12381", &poly_deg, &poly_count);
    benchmark_djba21::<Bls12_377>(c, "bls12377", &poly_deg, &poly_count);
    benchmark_djba21::<Bn254>(c, "bn254", &poly_deg, &poly_count);
}

criterion_group!(bench, benchmark);
criterion_main!(bench);