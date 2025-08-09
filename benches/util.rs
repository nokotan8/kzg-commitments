use criterion::Criterion;
use kzg_commitments::poly_commit::PolyCommit;
use ark_ec::pairing::Pairing;
use ark_std::rand::Rng;
use ark_std::cmp::max;

use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};

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


pub fn benchmark_poly_commit_with_curve<E: Pairing, PC: PolyCommit<E>> (
    c: &mut Criterion,
    pairing_name: &str,
    curve_name: &str,
    pc_new: &dyn Fn() -> PC, 
    verifier_init: &dyn Fn(usize) -> PC::VerifierParams,
    mut rng: impl Rng
) {
    let poly_deg = [8, 16, 32, 64, 128, 256];
    let poly_count = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
    let poly_count_grp_size = [100, 100, 100, 100, 100, 50, 50, 50, 25, 25, 25];
    
    let mut max_poly_count = 0;
    for v in poly_deg {
        max_poly_count = max(max_poly_count, v);
    }
    let max_poly_deg = max_poly_count;
    let mut max_point_count = 0;
    for v in poly_count {
        max_point_count = max(max_point_count, v);
    }

    let poly_by_deg = poly_generator_by_degree::<E>(max_poly_count, &poly_deg, &mut rng);

    let points = point_generator::<E>(max_point_count, &mut rng);

    let mut group = c.benchmark_group(String::new() + pairing_name + " " + curve_name);

    let pairs = (0..poly_deg.len()).flat_map(|y| (0..poly_count.len()).map(move |x| (x, y)));
    
    for (count_index, degree_index) in pairs {
        let mut pc = pc_new();
        let (pk, _sk) = pc.setup(max_poly_deg);
        group.sample_size(poly_count_grp_size[count_index]);
        let deg = poly_deg[degree_index];
        let count = poly_count[count_index];
        let poly_of_deg = &poly_by_deg[degree_index];
        let poly = &poly_of_deg[0..count];
        let z = &points[0..count];
        let ver_params = verifier_init(count);
        let c = pc.commit(&pk, poly);
        let v = pc.evaluate(poly, z);
        let p = pc.open(&pk, poly, z, &v, &ver_params);

        let ref_tuple = (pc, poly, z, ver_params, pk, c, v, p);

        group.bench_with_input(
            format!("COMMIT {} | {}", count, deg),
            &ref_tuple,
            |b, &(ref djb, ref poly, ref _z, ref _ver_param, ref pk, ref _c, ref _v, ref _p)| {
                b.iter(|| djb.commit(&pk, &poly));
            },
        );
        
    }
}
