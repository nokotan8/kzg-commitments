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
    let mut ret = E::G1::ZERO;
    for (coeff, g) in poly.coeffs().iter().zip(srs.iter()) {
        ret += g.mul(coeff);
    }

    ret
}

pub fn multipoint_eval_preproc<E: Pairing>(points: &[E::ScalarField]) -> Vec<Vec<DenseOrSparsePolynomial<E::ScalarField>>> {
    let plog = points.len().ilog2() as usize;

    let mut ztVec: Vec<Vec<DensePolynomial<E::ScalarField>>> = Vec::with_capacity(plog+1);
    ztVec.push(points.iter().map(|v| DensePolynomial::from_coefficients_slice(&[v.neg(), E::ScalarField::ONE])).collect());

    let mut accum = points.len()/2;
    for i in 0..plog {
        let mut tmpVec = Vec::with_capacity(accum);
        for j in 0..accum {
            tmpVec.push(ztVec[i][2*j].clone() * ztVec[i][2*j+1].clone());
        }
        ztVec.push(tmpVec);
        accum /= 2;
    }

    let mut ret = Vec::new();
    for v in ztVec {
        ret.push(v.into_iter().map(|x| DenseOrSparsePolynomial::from(x)).collect());
    }

    ret
}

pub fn multipoint_eval<E: Pairing>(poly: &DensePolynomial<E::ScalarField>, points: &[E::ScalarField], ztVec: &Vec<Vec<DenseOrSparsePolynomial<E::ScalarField>>>) -> Vec<(E::ScalarField, E::ScalarField)> {
    let plog = points.len().ilog2() as usize;

    let mut divVec: VecDeque<DensePolynomial<E::ScalarField>> = VecDeque::with_capacity(points.len());

    divVec.push_back(DenseOrSparsePolynomial::from(poly).divide_with_q_and_r(&ztVec[plog][0]).unwrap().1);
    let mut accum = 1;
    for i in 0..plog {
        for j in 0..accum {
            let cur = divVec.pop_front().unwrap();
            divVec.push_back(DenseOrSparsePolynomial::from(cur.clone()).divide_with_q_and_r(&ztVec[plog-i-1][2*j]).unwrap().1);
            divVec.push_back(DenseOrSparsePolynomial::from(cur).divide_with_q_and_r(&ztVec[plog-i-1][2*j+1]).unwrap().1);
        }
        accum *= 2;
    }

    points.iter().zip(divVec.iter()).map(|(x,y)| (*x, if y.len() > 0 {y[0]} else {E::ScalarField::ZERO})).collect()
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
