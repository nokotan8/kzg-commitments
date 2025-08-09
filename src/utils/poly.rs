use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use ark_ec::AdditiveGroup;
use std::ops::Mul;
use std::ops::Neg;
use std::collections::VecDeque;

#[inline(always)]
pub fn eval_poly_over_g1<E: Pairing>(poly: &DensePolynomial<E::ScalarField>, srs: &Vec<E::G1>) -> E::G1 {
    poly.coeffs().iter().zip(srs.iter()).fold(E::G1::ZERO, |acc, (c, g)| acc + g.mul(c))
}

pub fn lagrange_interpolate<E: Pairing>(points: &[(E::ScalarField, E::ScalarField)]) ->DensePolynomial<E::ScalarField> {

    let mut ret = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ZERO]);

    let mut ztVec: Vec<DensePolynomial<E::ScalarField>> = points.iter().map(|(x, _)| DensePolynomial::from_coefficients_slice(&[x.neg(), E::ScalarField::ONE])).collect();
    let mut accum = 2;
    for i in 0..points.len().ilog2() {
        for j in 0..(points.len()/accum) {
            ztVec[j] = ztVec[2*j].clone() * ztVec[2*j+1].clone();
        }
        accum *= 2;
    }

    let tot = ztVec[0].clone();

    for (x, y) in points {
        let cur = tot.clone() / DensePolynomial::from_coefficients_slice(&[x.neg(), E::ScalarField::ONE]);

        let denom = cur.evaluate(x).inverse().unwrap();

        ret = ret + cur * (denom * *y);
    }

    ret
}
