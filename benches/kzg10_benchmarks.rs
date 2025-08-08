use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use kzg_commitments::kzg10::KZG10;
use kzg_commitments::poly_commit::PolyCommit;
use std::hint::black_box;

fn kzg10_helper(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let mut rng = test_rng();
    
    let mut poly: Vec<DensePolynomial<Fr>> = vec![];
    for _ in 0..poly_count {
        poly.push(DensePolynomial::<Fr>::rand(poly_deg, &mut rng));
    }

    let mut z: Vec<Fr> = vec![];
    for _ in 0..point_count {
        z.push(Fr::rand(&mut rng));
    }

    let mut kzg = KZG10::<Bls12_381>::new();

    let (pk, _) = kzg.setup(poly_deg);

    let c = kzg.commit(&pk, &poly);

    let v = kzg.evaluate(&poly, &z);

    let p = kzg.open(&pk, &poly, &z, &v, &());

    KZG10::verify(&c, &pk, &p, &z, &v, &())
}

fn benchmark_kzg10(c: &mut Criterion) {
    // let poly_deg_vals = [8, 16];
    // let poly_count_vals = [1, 2, 4, 8];
    // let point_count_vals = [1, 2, 4, 8];

    c.bench_function(&format!("kzg10_helper {} {} {}", 10, 10, 10), |b| {
        b.iter(|| black_box(kzg10_helper(10, 10, 10)))
    });

    // for &poly_count in &poly_count_vals {
    //     for &poly_deg in &poly_deg_vals {
    //         for &point_count in &point_count_vals {
    //             c.bench_function(
    //                 &format!("kzg10_helper {} {} {}", poly_count, poly_deg, point_count),
    //                 |b| b.iter(|| black_box(kzg10_helper(poly_count, poly_deg, point_count))),
    //             );
    //         }
    //     }
    // }
}

criterion_group!(benches, benchmark_kzg10);
criterion_main!(benches);
