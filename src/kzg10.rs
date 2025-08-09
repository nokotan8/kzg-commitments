use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::{marker::PhantomData, ops::Mul};

pub struct KZG10<E: Pairing> {
    max_deg: usize,
    _phantom: PhantomData<E>
}

<<<<<<< HEAD
pub struct KzgPK<E: Pairing> {
=======
pub struct KZG_PK<E: Pairing> {
>>>>>>> main
    pub g1_vec: Vec<E::G1>,
    pub g2_1: E::G2,
    pub g2_x: E::G2
}

impl <E: Pairing> PolyCommit<E> for KZG10<E> {
<<<<<<< HEAD
    type PK = KzgPK<E>;
=======
    type PK = KZG_PK<E>;
>>>>>>> main
    type SK = E::ScalarField;
    type Commitment = Vec<E::G1>;
    type Evaluation = Vec<E::ScalarField>;
    type Proof = Vec<Vec<E::G1>>;
    type VerifierParams = ();

    fn new() -> Self {
        Self {
            max_deg: 0,
            _phantom: PhantomData
        }
    }

    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK) {
        let sk =  E::ScalarField::rand(&mut test_rng());
        let g1 = E::G1::rand(&mut test_rng());
        let g2 = E::G2::rand(&mut test_rng());
        let mut g1_vec = vec![];
        self.max_deg = max_deg;
        for i in 0..(max_deg + 1) {
            g1_vec.push(g1.mul(sk.pow(&[i as u64])));
        };
        (Self::PK {g1_vec: g1_vec, g2_1: g2, g2_x: g2.mul(sk)}, sk)
    }

    fn commit(&self, pk: &Self::PK, polynomials: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment {
        let mut commitments = vec![];
        for polynomial in polynomials {
            if polynomial.degree() > self.max_deg {
                panic!("Polynomial exceeds maximum degree!");
            }
            let mut commitment = E::G1::zero();
            for i in 0..(polynomial.degree() + 1) {
                commitment += pk.g1_vec[i].mul(polynomial[i]);
            }
            commitments.push(commitment);
        }

        if commitments.len() != polynomials.len() {
            panic!("Commitment failed!")
        }
        
        commitments
    }

    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation> {
        let v = poly.iter().map(|p| z.iter().map(|z| p.evaluate(z)).collect()).collect::<Vec<Vec<E::ScalarField>>>();

        if v.len() * v[0].len() != poly.len() * z.len() {
            panic!("Evaluation failed!");
        }

        v
    }

    // it is assumed that poly(z) = v
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], _: &[Self::Evaluation], _: &()) -> Self::Proof {
        let mut proofs = vec![];
        for i in 0..poly.len() {
            let mut poly_proofs = vec![];
            for j in 0..z.len() {
                // for each (polynomial phi, point i) combination, we calculate the polynomial phi(x)-phi(y) and (x-y), and then divide them through.
                let phi_x = &poly[i];
                let y = z[j];
                let phi_y = DensePolynomial::from_coefficients_slice(&[poly[i].evaluate(&y)]);

                let phi_x_minus_phi_y = phi_x - phi_y;
                let x_minus_y = DensePolynomial::from_coefficients_slice(&[-y, E::ScalarField::ONE]);

                let (quot, _rem) = DenseOrSparsePolynomial::from(phi_x_minus_phi_y).divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_y)).unwrap();

                let mut c = E::G1::zero();
                for i in 0..quot.coeffs.len() {
                    c += pk.g1_vec[i].mul(quot.coeffs[i]);
                }
                poly_proofs.push(c);
            }
            proofs.push(poly_proofs);
        }

        if proofs.len() * proofs[0].len() != poly.len() * z.len() {
            panic!("Opening/proof witness creation failed!");
        }

        proofs
    }

<<<<<<< HEAD
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], _: &()) -> bool {
=======
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], _ver_params: &()) -> bool {
>>>>>>> main
        for i in 0..c.len() {
            for j in 0..z.len() {
                let lhs = E::pairing(c[i] - pk.g1_vec[0].mul(&v[i][j]), pk.g2_1);
                let rhs = E::pairing(&p[i][j], pk.g2_x - pk.g2_1.mul(z[j]));
                if lhs != rhs {
                    return false;
                }
            }
        }
        true
    }
}
