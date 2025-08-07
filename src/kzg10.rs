use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::ops::Mul;

#[derive(Debug)]
pub struct KZG10<E: Pairing> {
    sk: E::ScalarField,
    max_deg: i32,
    pk_g2: E::G2,
    pk_g1_tuple: Vec<E::G1>,
}

impl <E: Pairing> PolyCommit<E, (Vec<E::G1>, E::G2), E::ScalarField, E::G1, Vec<E::G1>> for KZG10<E> {
    fn new() -> Self {
        Self { 
            sk: E::ScalarField::zero(), 
            max_deg: 0, 
            pk_g2: E::G2::zero(), 
            pk_g1_tuple: vec![]
        }
    }

    fn setup(&mut self, max_deg: i32) -> ((Vec<E::G1>, E::G2), E::ScalarField) {
        self.sk = E::ScalarField::rand(&mut test_rng());
        self.max_deg = max_deg;
        let g: <E as Pairing>::G1 = E::G1::rand(&mut test_rng());
        for i in 0..(max_deg + 1) {
            self.pk_g1_tuple.push(g.mul(self.sk.pow(&[i as u64])));
        };
        self.pk_g2 = E::G2::rand(&mut test_rng());
        return ((self.pk_g1_tuple.clone(), self.pk_g2), self.sk);
    }

    fn commit(&self, pk: &(Vec<E::G1>, E::G2), poly: &DensePolynomial<<E as Pairing>::ScalarField>) -> E::G1 {
        let mut c = E::G1::zero();
        for i in 0..poly.len() {
            c += pk.0[i].mul(poly[i]);         
        }
        c
    }

    // it is assumed that poly(z) = v
    fn open(&self, pk: &(Vec<E::G1>, E::G2), poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], _v: &[<E as Pairing>::ScalarField]) -> Vec<E::G1> {
        let mut proofs = vec![];
        for i in 0..poly.len() {
            for j in 0..z.len() {
                // for each (polynomial phi, point i) combination, we calculate the polynomial phi(x)-phi(y) and (x-y), and then divide them through.
                let phi_x = &poly[i];
                let y = z[j];
                let phi_y = DensePolynomial::from_coefficients_slice(&[poly[i].evaluate(&y)]);
                let phi_x_minus_phi_y = phi_x - phi_y;
                let x_minus_y = DensePolynomial::from_coefficients_slice(&[-y, E::ScalarField::ONE]);
                let (quotient, _rem) = DenseOrSparsePolynomial::from(phi_x_minus_phi_y).divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_y)).unwrap();
                let mut c = E::G1::zero();
                for i in 0..quotient.coeffs.len() {
                    c += pk.0[i].mul(quotient.coeffs[i]);         
                }
                proofs.push(c);
            }
        }

        proofs
    }

    fn verify(&self, c: &[E::G1], pk: &(Vec<E::G1>, E::G2), p: &Vec<E::G1>, z: &[<E as Pairing>::ScalarField], v: &[<E as Pairing>::ScalarField]) -> bool {
        for i in 0..c.len() {
            for j in 0..z.len() {
                let index = i * z.len() + j;
                let lhs = E::pairing(c[i] - pk.0[0].mul(v[index]), pk.1.mul(E::ScalarField::ONE));
                let rhs = E::pairing(p[index], pk.1.mul(self.sk - z[j]));
                if lhs != rhs {
                    return false;
                }
            }
        }
        true
    }
}