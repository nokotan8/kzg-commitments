use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;
use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use kzg_commitments::kzg10::{KZG_PK, KZG10};
use kzg_commitments::poly_commit::PolyCommit;

fn poly_generator<Curve: Pairing>(
    poly_count: usize,
    poly_deg: usize,
    rng: &mut impl Rng,
) -> Vec<DensePolynomial<Curve::ScalarField>> {
    let mut poly = vec![];
    for _ in 0..poly_count {
        poly.push(DensePolynomial::<Curve::ScalarField>::rand(poly_deg, rng));
    }
    poly
}

fn point_generator<Curve: Pairing>(
    point_count: usize,
    rng: &mut impl Rng,
) -> Vec<Curve::ScalarField> {
    let mut z: Vec<Curve::ScalarField> = vec![];
    for _ in 0..point_count {
        z.push(Curve::ScalarField::rand(rng));
    }
    z
}

fn kzg10_helper<Curve: Pairing>(
    poly_count: usize,
    poly_deg: usize,
) -> (
    KZG10<Curve>,
    Vec<DensePolynomial<<Curve as Pairing>::ScalarField>>,
    Vec<<Curve as Pairing>::ScalarField>,
    KZG_PK<Curve>,
    Vec<<Curve as Pairing>::G1>,
    Vec<Vec<<Curve as Pairing>::ScalarField>>,
    Vec<Vec<<Curve as Pairing>::G1>>,
) {
    let mut rng = test_rng();

    let poly = poly_generator::<Curve>(poly_count, poly_deg, &mut rng);

    let z = point_generator::<Curve>(poly_count, &mut rng);

    let mut kzg = KZG10::<Curve>::new();

    let (pk, _) = kzg.setup(poly_deg);

    let c = kzg.commit(&pk, &poly);

    let v = kzg.evaluate(&poly, &z);

    let p = kzg.open(&pk, &poly, &z, &v, ());

    return (kzg, poly, z, pk, c, v, p);
}

fn kzg10_benchmark_curve<Curve: Pairing>(cr: &mut Criterion, id: String) {
    let poly_deg_vals = [8, 16, 32, 64, 128];
    let poly_count_vals = [1, 2, 4, 8, 16, 32, 64, 128];

    let mut group = cr.benchmark_group(id);

    // 1 - 16
    group.sample_size(100);
    for &poly_count in &poly_count_vals[0..5] {
        for &poly_deg in &poly_deg_vals {
            let (kzg, poly, z, pk, c, v, p) = kzg10_helper::<Curve>(poly_count, poly_deg);

            let ref_tuple = &(kzg, poly, z, pk, c, v, p);

            group.bench_with_input(
                format!("COMMIT {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref kzg, ref poly, ref _z, ref pk, ref _c, ref _v, ref _p)| {
                    b.iter(|| kzg.commit(&pk, &poly));
                },
            );

            group.bench_with_input(
                format!("OPEN {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref kzg, ref poly, ref z, ref pk, ref _c, ref v, ref _p)| {
                    b.iter(|| kzg.open(&pk, &poly, &z, &v, ()));
                },
            );

            group.bench_with_input(
                format!("VERIFY {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref _kzg, ref _poly, ref z, ref pk, ref c, ref v, ref p)| {
                    b.iter(|| KZG10::verify(&c, &pk, &p, &z, &v));
                },
            );
        }
    }

    // 32 - 128
    group.sample_size(25);
    for &poly_count in &poly_count_vals[5..] {
        for &poly_deg in &poly_deg_vals {
            let (kzg, poly, z, pk, c, v, p) = kzg10_helper::<Curve>(poly_count, poly_deg);

            let ref_tuple = &(kzg, poly, z, pk, c, v, p);

            group.bench_with_input(
                format!("COMMIT {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref kzg, ref poly, ref _z, ref pk, ref _c, ref _v, ref _p)| {
                    b.iter(|| kzg.commit(&pk, &poly));
                },
            );

            group.bench_with_input(
                format!("OPEN {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref kzg, ref poly, ref z, ref pk, ref _c, ref v, ref _p)| {
                    b.iter(|| kzg.open(&pk, &poly, &z, &v, ()));
                },
            );

            group.bench_with_input(
                format!("VERIFY {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref _kzg, ref _poly, ref z, ref pk, ref c, ref v, ref p)| {
                    b.iter(|| KZG10::verify(&c, &pk, &p, &z, &v));
                },
            );
        }
    }

    group.finish();
}

fn djba21_benchmark_all(c: &mut Criterion) {
    kzg10_benchmark_curve::<Bls12_381>(c, "kzg10-bls12381".to_string());
    kzg10_benchmark_curve::<Bn254>(c, "kzg10-bn254".to_string());
    kzg10_benchmark_curve::<Bls12_377>(c, "kzg10-bls12377".to_string());
}

criterion_group!(benches, djba21_benchmark_all);
criterion_main!(benches);
