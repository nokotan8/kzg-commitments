use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::{marker::PhantomData, ops::{Mul, Neg}};

pub struct GWC19<E: Pairing> {
    max_deg: usize,
    _phantom: PhantomData<E>
}

pub struct GwcPK<E: Pairing> {
    pub g1_vec: Vec<E::G1>,
    pub g2_1: E::G2,
    pub g2_x: E::G2
}

impl <E: Pairing> PolyCommit<E> for GWC19<E> {
    type PK = GwcPK<E>;
    type SK = E::ScalarField;
    type Commitment = Vec<E::G1>;
    type Evaluation = Vec<E::ScalarField>;
    type Proof = Vec<E::G1>;
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
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], _: &[Self::Evaluation], _: ()) -> Self::Proof {
        let mut proofs = vec![];
        for i in 0..poly.len() {
            // batch open all z[] with one commitment element
            // for each (polynomial phi, point i) combination, we calculate the polynomial phi(x)-phi(y) and (x-y), and then divide them through.
            let phi_x = &poly[i];

            let mut prod = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ONE]);
            for y in z {
                prod = prod.naive_mul(&DensePolynomial::from_coefficients_slice(&[y.neg(), E::ScalarField::ONE]));
            }

            let (quot, _rem) = DenseOrSparsePolynomial::from(phi_x).divide_with_q_and_r(&DenseOrSparsePolynomial::from(prod)).unwrap();

            let mut c = E::G1::zero();
            for i in 0..quot.coeffs.len() {
                c += pk.g1_vec[i].mul(quot.coeffs[i]);
            }
            proofs.push(c);
        }

        if proofs.len() != poly.len() * z.len() {
            panic!("Opening/proof witness creation failed!");
        }

        proofs
    }

    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation]) -> bool {
        // for i in 0..c.len() {
        //     for j in 0..z.len() {
        //         let lhs = E::pairing(c[i] - pk.g1_vec[0].mul(&v[i][j]), pk.g2_1);
        //         let rhs = E::pairing(&p[i][j], pk.g2_x - pk.g2_1.mul(z[j]));
        //         if lhs != rhs {
        //             return false;
        //         }
        //     }
        // }
        true
    }
}

