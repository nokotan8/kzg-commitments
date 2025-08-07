use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
use ark_std::test_rng;

pub fn kzg10(poly_count: usize, poly_deg: usize, point_count: usize) -> bool {
    let rng = &mut test_rng();

    let mut polys: Vec<DensePolynomial<Fr>> = Vec::with_capacity(poly_count);
    let mut commitments: Vec<G1Projective> = Vec::with_capacity(poly_count);
    for i in 0..poly_count {
        polys.push(DensePolynomial::<Fr>::rand(poly_deg, rng));
        // commitments.push(smth)
        println!("{:?}", commitments[i]);
    }

    let mut points: Vec<Fr> = Vec::with_capacity(point_count);
    for _i in 0..point_count {
        points.push(Fr::rand(rng));
    }

    let mut evals: Vec<Vec<Fr>> = Vec::with_capacity(poly_count);
    for i in 0..poly_count {
        evals.push(Vec::with_capacity(point_count));
        for j in 0..point_count {
            let p: Fr; // = open(pk, &polys[i..i+1], &points[j..j+1], _);

            evals[i].push(p);
            let res = true; // = verify(&commitments[i..i+1], pk, p, &points[j..j+1], &evals[j..j+1]);

            if !res {
                return false;
            }
        }
    }

    return true;
}
