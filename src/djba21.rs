use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use ark_ec::AdditiveGroup;
use std::ops::Mul;
use std::ops::Neg;

use crate::utils::poly::{eval_poly_over_g1, lagrange_interpolate};

#[derive(Debug)]
pub struct DJBA21<E: Pairing> {
    sk: E::ScalarField,
    max_deg: usize,
    pk: DJBA21_PK<E>,
}

#[derive(Debug,Clone)]
pub struct DJBA21_PK<E: Pairing> {
    g1: Vec<E::G1>,
    g2_one: E::G2,
    g2_x: E::G2,
}


                            
//Pairing: E
//PK: (Vec<E::G1>, (E::G2, E::G2))
//SK: E::ScalarField
//Commitment: E::G1
//Add VerifierParams (E::G1, E::G1)
//Proof: (E::G1, E::G1)
impl<E: Pairing> PolyCommit<E> for DJBA21<E> {
    type PK = DJBA21_PK<E>;
    type SK = E::ScalarField;
    type Commitment = Vec<E::G1>;
    type Evaluation = DensePolynomial<E::ScalarField>;
    type Proof = (E::G1, E::G1);
    type VerifierParams = (E::ScalarField, E::ScalarField);

    fn new() -> Self {
        Self {
            sk: E::ScalarField::ZERO,
            max_deg: 0,
            pk: Self::PK {
                g1: Vec::new(),
                g2_one: E::G2::ZERO,
                g2_x: E::G2::ZERO,
            }
        }
    }

    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK) {
        self.sk = E::ScalarField::rand(&mut test_rng());
        self.max_deg = max_deg;
        
        let g = E::G1::rand(&mut test_rng());

        for i in 0..(max_deg + 1) {
            self.pk.g1.push(g.mul(self.sk.pow(&[i as u64])));
        }

        self.pk.g2_one = E::G2::rand(&mut test_rng());
        self.pk.g2_x = self.pk.g2_one.mul(self.sk);

        (self.pk.clone(), self.sk)
    }


    fn commit(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment {
        let mut ret = Vec::with_capacity(poly.len());

        for p in poly {
            ret.push(eval_poly_over_g1::<E>(p, &pk.g1));
        }

        ret
    }

    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation> {
        let mut ret = Vec::new();
        let mut points = Vec::new();
        for p in poly {
            for x in z {
                points.push((*x, p.evaluate(x)));
            }

            ret.push(lagrange_interpolate::<E>(points.as_slice()));
            points.clear();
        }
        ret
    }


    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> Self::Proof {
        // let mut f = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::ZERO; poly[0].degree()+1]);
        // let mut L = DensePolynomial::from_coefficients_vec(vec![E::ScalarField::ZERO; poly[0].degree()+1]);

        let mut f = vec![E::ScalarField::ZERO; poly[0].degree()+1];
        let mut L = vec![E::ScalarField::ZERO; poly[0].degree()+1];

        // use std::time::Instant;
        let mut accum = E::ScalarField::ONE;
        for i in 0..z.len() {
            // f = f + poly[i].clone() * accum;
            for (j, c) in poly[i].coeffs().iter().enumerate() {
                f[j] += *c * accum;
            }

            // f = f - v[i].clone() * accum;
            for (j, t) in v[i].coeffs().iter().enumerate() {
                f[j] -= *t * accum;
            }

            // L = L + poly[i].clone() * accum;
            for (j, c) in poly[i].coeffs().iter().enumerate() {
                L[j] += *c * accum;
            }
            L[0] -= v[i].evaluate(&ver_params.1) * accum;

            accum *= ver_params.0;
        }

        // let now = Instant::now();
        let mut zt = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ONE]);
        for val in z {
            zt = zt * DensePolynomial::from_coefficients_slice(&[val.neg(), E::ScalarField::ONE]);
        }
        // println!("ZT EVALUATION: {:?}", now.elapsed());

        let mut w_partial = DensePolynomial::from_coefficients_vec(f) / zt.clone();

        // let now = Instant::now();
        let W = eval_poly_over_g1::<E>(&w_partial, &pk.g1);
        // println!("SECTION 1: {:?}", now.elapsed());

        w_partial = w_partial * zt.evaluate(&ver_params.1);

        // L = L - w_partial;
        for (j, c) in w_partial.coeffs().iter().enumerate() {
            L[j] -= c;
        }

        let mut L = DensePolynomial::from_coefficients_vec(L);

        // let now = Instant::now();
        L = L / DensePolynomial::from_coefficients_slice(&[ver_params.1.neg(), E::ScalarField::ONE]);
        // println!("DIVISION: {:?}", now.elapsed());

        let Wp = eval_poly_over_g1::<E>(&L, &pk.g1);
        
        (W, Wp)
    }

    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> bool {
        let (W, Wp) = *p;

        let mut F = E::G1::ZERO;

        let mut mid = E::ScalarField::ZERO;

        let mut accum = E::ScalarField::ONE;
        for (i, comm) in c.iter().enumerate() {
            F += comm.mul(accum);
            mid += accum * v[i].evaluate(&ver_params.1);

            accum *= ver_params.0;
        }

        F = F - pk.g1[0].mul(mid);

        let mut zt = DensePolynomial::from_coefficients_slice(&[E::ScalarField::ONE]);
        for val in z {
            zt = zt * DensePolynomial::from_coefficients_slice(&[val.neg(), E::ScalarField::ONE]);
        }

        F -= W.mul(zt.evaluate(&ver_params.1));


        let lhs = E::pairing(F + Wp.mul(ver_params.1), pk.g2_one);
        let rhs = E::pairing(Wp, pk.g2_x);

        lhs == rhs
    }
}
