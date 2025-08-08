use kzg_commitments::kzg10::KZG10;
use kzg_commitments::poly_commit::PolyCommit;
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, Polynomial, univariate::DensePolynomial};
use ark_std::test_rng;

pub fn kzg10(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let mut kzg = KZG10::<Bls12_381>::new();
    let (pk, _sk) = kzg.setup(poly_deg as i32);
    let rng = &mut test_rng();

    let mut polys: Vec<DensePolynomial<Fr>> = Vec::with_capacity(poly_count);
    let mut commitments: Vec<G1Projective> = Vec::with_capacity(poly_count);
    for i in 0..poly_count {
        polys.push(DensePolynomial::<Fr>::rand(poly_deg, rng));
        commitments.push(kzg.commit(&pk, &DensePolynomial::from_coefficients_slice(&polys[i])));
    }

    let mut points: Vec<Fr> = Vec::with_capacity(point_count);
    for _i in 0..point_count {
        points.push(Fr::rand(rng));
    }

    let values: Vec<Fr> = polys
        .clone()
        .into_iter()
        .map(|poly| {
            points
                .clone()
                .into_iter()
                .map(move |point| poly.evaluate(&point))
        })
        .flatten()
        .collect();

    let proofs = kzg.open(&pk, &polys, &points, &values);

    println!(
        "res: {}",
        kzg.verify(&commitments, &pk, &proofs, &points, &values)
            .to_string()
    );

    return true;
}
