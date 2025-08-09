use kzg_commitments::{poly_commit::PolyCommit, kzg10::KZG10, gwc19::GWC19, djba21::DJBA21};

use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, test_rng, cmp::max};
use ark_ff::UniformRand;

use criterion::Criterion;

pub fn benchmark_kzg10<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    benchmark_poly_commit_with_curve::<E, KZG10<E>>(c, "kzg10", curve_name, &|_|(), &mut test_rng(), poly_deg, poly_count);
}

pub fn benchmark_gwc19<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    fn verifier_init<E: Pairing>(t: usize) -> <GWC19<E> as PolyCommit<E>>::VerifierParams {
        point_generator::<E>(t, &mut test_rng())
    }
    benchmark_poly_commit_with_curve::<E, GWC19<E>>(c, "gwc19", curve_name, &verifier_init::<E>, &mut test_rng(), poly_deg, poly_count);
}

pub fn benchmark_djba21<E: Pairing>(c: &mut Criterion, curve_name: &str, poly_deg: &[usize], poly_count: &[(usize, usize)]) {
    fn verifier_init<E: Pairing>(_t: usize) -> <DJBA21<E> as PolyCommit<E>>::VerifierParams {
        let v = point_generator::<E>(2, &mut test_rng());
        (v[0], v[1])
    }
    benchmark_poly_commit_with_curve::<E, DJBA21<E>>(c, "djba21", curve_name, &verifier_init::<E>, &mut test_rng(), poly_deg, poly_count);
}

pub fn poly_generator_by_degree<E: Pairing>(
    max_poly_count: usize, 
    poly_degrees: &[usize],
    rng: &mut impl Rng
) -> Vec<Vec<DensePolynomial<E::ScalarField>>> {
    poly_degrees.iter().map(move |&poly_deg| 
        poly_generator::<E>(max_poly_count, poly_deg, rng)
    ).collect()
}

pub fn poly_generator<E: Pairing>(
    poly_count: usize,
    poly_deg: usize,
    rng: &mut impl Rng,
) -> Vec<DensePolynomial<E::ScalarField>> {
    let mut poly = vec![];
    for _ in 0..poly_count {
        poly.push(DenseUVPolynomial::<E::ScalarField>::rand(poly_deg, rng));
    }
    poly
}

pub fn point_generator<E: Pairing>(
    point_count: usize,
    rng: &mut impl Rng,
) -> Vec<E::ScalarField> {
    let mut z: Vec<E::ScalarField> = vec![];
    for _ in 0..point_count {
        z.push(E::ScalarField::rand(rng));
    }
    z
}

pub fn benchmark_poly_commit_with_curve<E: Pairing, P: PolyCommit<E>> (
    c: &mut Criterion,
    pairing_name: &str,
    curve_name: &str,
    verifier_init: &dyn Fn(usize) -> P::VerifierParams,
    mut rng: impl Rng,
    poly_deg: &[usize],
    poly_count: &[(usize, usize)],
) {    
    let mut max_poly_deg = 0;
    for &v in poly_deg {
        max_poly_deg = max(max_poly_deg, v);
    }
    let mut max_point_count = 0;
    for &(v, _) in poly_count {
        max_point_count = max(max_point_count, v);
    }
    let max_poly_count = max_point_count;
    let poly_by_deg = poly_generator_by_degree::<E>(max_poly_count, &poly_deg, &mut rng);

    let points = point_generator::<E>(max_point_count, &mut rng);

    let mut group = c.benchmark_group(String::new() + pairing_name + "-" + curve_name);

    let pairs = (0..poly_deg.len()).flat_map(|y| (0..poly_count.len()).map(move |x| (x, y)));
    
    for (count_index, degree_index) in pairs {
        let mut pc = P::new();
        let (pk, _sk) = pc.setup(max_poly_deg);
        group.sample_size(poly_count[count_index].1);
        let deg = poly_deg[degree_index];
        let count = poly_count[count_index].0;
        if deg > max_poly_deg || count > max_poly_count {
            continue;
        }
        let poly_of_deg = &poly_by_deg[degree_index];
        let poly = &poly_of_deg[0..count];
        let z = &points[0..count];
        let ver_params = verifier_init(count);
        let c = pc.commit(&pk, poly);
        let v = pc.evaluate(poly, z);
        let p = pc.open(&pk, poly, z, &v, &ver_params);

        let ref_tuple = (&pc, &poly, &z, &ver_params, &pk, &c, &v, &p);

        group.bench_with_input(
            format!("COMMIT {} | {}", count, deg),
            &ref_tuple,
            |b, (djb,  poly,  _z, _ver_param, pk, _c, _v, _p)| {
                b.iter(|| djb.commit(&pk, &poly));
            },
        );

        group.bench_with_input(
            format!("OPEN {} | {}", count, deg),
            &ref_tuple,
            |b, (djb,  poly,  z, ver_params, pk, _c, v, _p)| {
                b.iter(|| djb.open(&pk, &poly, &z, &v, &ver_params));
            },
        );

        group.bench_with_input(
            format!("VERIFY {} | {}", count, deg),
            &ref_tuple,
            |b, (_djb, _poly, z, ver_params, pk, c, v, p)| {
                b.iter(|| P::verify(&c, &pk, &p, &z, &v, &ver_params));
            },
        );
    }
}
