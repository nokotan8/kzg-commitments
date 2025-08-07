use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use ark_ec::AdditiveGroup;
use std::ops::Mul;
use std::ops::Neg;

pub fn eval_poly_over_g1<E: Pairing>(poly: &DensePolynomial<E::ScalarField>, srs: &Vec<E::G1>) -> E::G1 {
    let mut ret = E::G1::ZERO;
    for (coeff, g) in poly.coeffs().iter().zip(srs.iter()) {
        ret += g.mul(coeff);
    }

    ret
}

pub fn lagrange_interpolate<E: Pairing>(points: &[(E::ScalarField, E::ScalarField)]) ->DensePolynomial<E::ScalarField> {

    let mut ret = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ZERO]);

    let mut tot = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ONE]);
    for (x, _) in points {
        tot = tot * DensePolynomial::from_coefficients_slice(&[x.neg(), E::ScalarField::ONE]);
    }

    for (x, y) in points {
        let cur = tot.clone() / DensePolynomial::from_coefficients_slice(&[x.neg(), E::ScalarField::ONE]);

        let denom = cur.evaluate(x).inverse().unwrap();

        ret = ret + cur * denom * *y;
    }

    ret
}
