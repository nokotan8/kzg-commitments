use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::{marker::PhantomData, ops::Mul};

use crate::utils::poly::eval_poly_over_g1;

/// Struct for implementing the polynomial commitment scheme described in
/// [this paper](https://iacr.org/archive/asiacrypt2010/6477178/6477178.pdf),
/// with modifications made as per our report.
pub struct KZG10<E: Pairing> {
    max_deg: usize,
    _phantom: PhantomData<E>
}

pub struct KZG_PK<E: Pairing> {
    /// Corresponds to <g_1, g_1^a, g_1^{a^2}, .... , g_1^{a^t}>
    pub g1_vec: Vec<E::G1>,
    /// Corresponds to g_2
    pub g2_1: E::G2,
    /// Corresponds to g_2^a
    pub g2_x: E::G2
}

/// Implementation of batched polynomial commitments for KZG10
impl <E: Pairing> PolyCommit<E> for KZG10<E> {
    type PK = KZG_PK<E>;
    type SK = E::ScalarField;
    /// The commitment consists of 1 element of G_1 for each polynomial
    /// committed to.
    type Commitment = Vec<E::G1>;
    /// List of the values of a polynomial at each input point.
    type Evaluation = Vec<E::ScalarField>;
    /// We provide a proof element in G_1 for each polynomial and point,
    type Proof = Vec<Vec<E::G1>>;
    /// KZG is not interactive, and so requires no verifier parameters.
    type VerifierParams = ();

    fn new() -> Self {
        Self {
            max_deg: 0,
            _phantom: PhantomData
        }
    }

    /// Initialises the public key parameters by as described in the paper,
    /// for polynomials of degree up to `max_deg`.
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

    /// Commits to the polynomials in `poly`, yields one element of G_1 per
    /// polynomial.
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

    /// Evaluates the polynomials in `poly` at each of the points in `z`, and returns
    /// those values in a vector.
    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation> {
        let v = poly.iter().map(|p| z.iter().map(|z| p.evaluate(z)).collect()).collect::<Vec<Vec<E::ScalarField>>>();

        if v.len() * v[0].len() != poly.len() * z.len() {
            panic!("Evaluation failed!");
        }

        v
    }

    /// Creates witnesses to the values of the polynomials in `poly` at all
    /// the points in `z`.
    ///
    /// It is a logic error for:
    ///  - `poly.len() != z.len()`
    ///  - the values in `v` to be incorrect.
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], _: &[Self::Evaluation], _: &()) -> Self::Proof {
        let mut proofs = vec![];
        for i in 0..poly.len() {
            let mut poly_proofs = vec![];
            for j in 0..z.len() {
                // For each (polynomial phi, point i) combination, we calculate the polynomial phi(x)-phi(y) and (x-y), and then divide them through.
                let phi_x = &poly[i];
                let y = z[j];
                let phi_y = DensePolynomial::from_coefficients_slice(&[poly[i].evaluate(&y)]);

                let phi_x_minus_phi_y = phi_x - phi_y;
                let x_minus_y = DensePolynomial::from_coefficients_slice(&[-y, E::ScalarField::ONE]);

                let (quot, _rem) = DenseOrSparsePolynomial::from(phi_x_minus_phi_y).divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_y)).unwrap();

                poly_proofs.push(eval_poly_over_g1::<E>(&quot, &pk.g1_vec));
            }
            proofs.push(poly_proofs);
        }

        if proofs.len() * proofs[0].len() != poly.len() * z.len() {
            panic!("Opening/proof witness creation failed!");
        }

        proofs
    }

    /// Verifies that the proof `p` is valid for the given parameters, and
    /// returns true if it is, and false if it is not. The equation used here
    /// differs from the one given in the 2010 paper: a proof of its security
    /// is presented in section 4.1 of our report.
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], _ver_params: &()) -> bool {
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
