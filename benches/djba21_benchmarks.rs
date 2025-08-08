use ark_bls12_377::Bls12_377;
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::rand::Rng;
use ark_std::test_rng;
use criterion::{Criterion, criterion_group, criterion_main};
use kzg_commitments::djba21::{DJBA21, DJBA21_PK};
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

fn djba21_helper<Curve: Pairing>(
    poly_count: usize,
    poly_deg: usize,
) -> (
    DJBA21<Curve>,
    Vec<DensePolynomial<<Curve>::ScalarField>>,
    Vec<<Curve>::ScalarField>,
    (<Curve>::ScalarField, <Curve>::ScalarField),
    DJBA21_PK<Curve>,
    Vec<<Curve>::G1>,
    Vec<DensePolynomial<<Curve>::ScalarField>>,
    (<Curve>::G1, <Curve>::G1),
) {
    let mut rng = test_rng();

    let poly = poly_generator::<Curve>(poly_count, poly_deg, &mut rng);

    let z = point_generator::<Curve>(poly_count, &mut rng);

    let mut djb = DJBA21::<Curve>::new();

    let ver_param = (
        Curve::ScalarField::rand(&mut rng),
        Curve::ScalarField::rand(&mut rng),
    );

    let (pk, _) = djb.setup(poly_deg);

    let c = djb.commit(&pk, &poly);

    let v = djb.evaluate(&poly, &z);

    let p = djb.open(&pk, &poly, &z, &v, ver_param);

    // let res = DJBA21::verify(&c, &pk, &p, &z, &v, ver_param);

    return (djb, poly, z, ver_param, pk, c, v, p);
}

fn djba21_benchmark_curve<Curve: Pairing>(c: &mut Criterion, id: String) {
    let poly_deg_vals = [8, 16, 32, 64, 128, 256];
    // fast
    let poly_count_vals = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1028];

    let mut group = c.benchmark_group(id);

    // 1 - 16
    group.sample_size(100);
    for &poly_count in &poly_count_vals[0..5] {
        for &poly_deg in &poly_deg_vals {
            let (djb, poly, z, ver_param, pk, c, v, p) =
                djba21_helper::<Curve>(poly_count, poly_deg);

            let ref_tuple = &(djb, poly, z, ver_param, pk, c, v, p);

            group.bench_with_input(
                format!("COMMIT {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref _z, ref _ver_param, ref pk, ref _c, ref _v, ref _p)| {
                    b.iter(|| djb.commit(&pk, &poly));
                },
            );

            group.bench_with_input(
                format!("OPEN {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref z, ref ver_param, ref pk, ref _c, ref v, ref _p)| {
                    b.iter(|| djb.open(&pk, &poly, &z, &v, *ver_param));
                },
            );

            group.bench_with_input(
                format!("VERIFY {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref _djb, ref _poly, ref z, ref ver_param, ref pk, ref c, ref v, ref p)| {
                    b.iter(|| DJBA21::verify(&c, &pk, &p, &z, &v, *ver_param));
                },
            );
        }
    }

    // 32 - 128
    group.sample_size(50);
    for &poly_count in &poly_count_vals[5..8] {
        for &poly_deg in &poly_deg_vals {
            let (djb, poly, z, ver_param, pk, c, v, p) =
                djba21_helper::<Curve>(poly_count, poly_deg);

            let ref_tuple = &(djb, poly, z, ver_param, pk, c, v, p);

            group.bench_with_input(
                format!("COMMIT {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref _z, ref _ver_param, ref pk, ref _c, ref _v, ref _p)| {
                    b.iter(|| djb.commit(&pk, &poly));
                },
            );

            group.bench_with_input(
                format!("OPEN {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref z, ref ver_param, ref pk, ref _c, ref v, ref _p)| {
                    b.iter(|| djb.open(&pk, &poly, &z, &v, *ver_param));
                },
            );

            group.bench_with_input(
                format!("VERIFY {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref _djb, ref _poly, ref z, ref ver_param, ref pk, ref c, ref v, ref p)| {
                    b.iter(|| DJBA21::verify(&c, &pk, &p, &z, &v, *ver_param));
                },
            );
        }
    }

    // // 256 - 1028
    group.sample_size(25);
    for &poly_count in &poly_count_vals[8..] {
        for &poly_deg in &poly_deg_vals {
            let (djb, poly, z, ver_param, pk, c, v, p) =
                djba21_helper::<Curve>(poly_count, poly_deg);

            let ref_tuple = &(djb, poly, z, ver_param, pk, c, v, p);

            group.bench_with_input(
                format!("COMMIT {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref _z, ref _ver_param, ref pk, ref _c, ref _v, ref _p)| {
                    b.iter(|| djb.commit(&pk, &poly));
                },
            );

            group.bench_with_input(
                format!("OPEN {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref djb, ref poly, ref z, ref ver_param, ref pk, ref _c, ref v, ref _p)| {
                    b.iter(|| djb.open(&pk, &poly, &z, &v, *ver_param));
                },
            );

            group.bench_with_input(
                format!("VERIFY {} | {}", poly_count, poly_deg),
                ref_tuple,
                |b, &(ref _djb, ref _poly, ref z, ref ver_param, ref pk, ref c, ref v, ref p)| {
                    b.iter(|| DJBA21::verify(&c, &pk, &p, &z, &v, *ver_param));
                },
            );
        }
    }

    group.finish();
}

fn djba21_benchmark_all(c: &mut Criterion) {
    djba21_benchmark_curve::<Bls12_381>(c, "djba21-bls12381".to_string());
    djba21_benchmark_curve::<Bn254>(c, "djba21-bn254".to_string());
    djba21_benchmark_curve::<Bls12_377>(c, "djba21-bls12377".to_string());
}

criterion_group!(benches, djba21_benchmark_all);
criterion_main!(benches);
