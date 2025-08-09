use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_std::test_rng;
use ark_ec::pairing::{Pairing};
use ark_ec::AdditiveGroup;
use std::ops::Mul;
use std::ops::Neg;
use std::marker::PhantomData;

use crate::utils::poly::{eval_poly_over_g1, lagrange_interpolate};

/// Struct for implementing the batched polynomial commitment scheme
/// described in [this paper](https://eprint.iacr.org/2020/081.pdf).
#[derive(Debug)]
pub struct DJBA21<E: Pairing> {
    max_deg: usize,
    _phantom: PhantomData<E>,
}

/// Struct which holds the PK information for DJBA21.
#[derive(Debug,Clone)]
pub struct DJBA21_PK<E: Pairing> {
    /// Corresponds to <g_1, g_1^a, g_1^{a^2}, .... , g_1^{a^t}>
    pub g1: Vec<E::G1>,
    /// Corresponds to g_2
    pub g2_one: E::G2,
    /// Corresponds to g_2^a
    pub g2_x: E::G2,
}


/// Implementation of batched polynomial commitments for DJBA21.
impl<E: Pairing> PolyCommit<E> for DJBA21<E> {
    type PK = DJBA21_PK<E>;
    type SK = E::ScalarField;
    /// The commitment consists of 1 element of G_1 for each polynomial
    /// committed to.
    type Commitment = Vec<E::G1>;
    /// As in the paper we encode the evaluation of a polynomial `f` at `t`
    /// points as a polynomial with degree `t` which agrees with `f` for
    /// all the `t` points.
    type Evaluation = DensePolynomial<E::ScalarField>;
    /// The witness for the evaluation of `t` polynomials at `t` points is
    /// two elements in G_1
    type Proof = (E::G1, E::G1);
    /// The verifier is required to provide 2 randomly uniformly selected
    /// parameters from Z_p.
    type VerifierParams = (E::ScalarField, E::ScalarField);

    fn new() -> Self {
        Self {
            max_deg: 0,
            _phantom: PhantomData,
        }
    }

    /// Initialises the public key parameters by as described in the paper,
    /// for polynomials of degree up to `max_deg`.
    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK) {
        let sk = E::ScalarField::rand(&mut test_rng());
        self.max_deg = max_deg;
        
        let g = E::G1::rand(&mut test_rng());

        let mut pk = Self::PK {
            g1: Vec::new(),
            g2_one: E::G2::ZERO,
            g2_x: E::G2::ZERO,
        };
        for i in 0..(max_deg + 1) {
            //g_1^{sk^i}
            pk.g1.push(g.mul(sk.pow(&[i as u64])));
        }

        pk.g2_one = E::G2::rand(&mut test_rng());
        pk.g2_x = pk.g2_one.mul(sk);

        (pk, sk)
    }

    /// Commits to the polynomials in `poly`, yields one element of G_1 per
    /// polynomial.
    fn commit(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment {
        let mut ret = Vec::with_capacity(poly.len());

        for p in poly {
            ret.push(eval_poly_over_g1::<E>(p, &pk.g1));
        }

        ret
    }

    /// Evaluates the polynomials in `poly` at each of the points in `z`. For each
    /// polynomial `f` in `poly`, the evaluations are then returned as a polynomial
    /// which agrees with `f` on all the points in `z`.
    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation> {
        let mut ret = Vec::new();
        let mut points = Vec::new();

        for p in poly {
            for point in z {
                points.push((*point, p.evaluate(point)));
            }

            ret.push(lagrange_interpolate::<E>(points.as_slice()));
            points.clear();
        }
        ret
    }

    /// Creates witnesses to the values of the polynomials in `poly` at all
    /// the points in `z`.
    /// The calculations carried out below are faithful to the equations
    /// presented in section 4.1 of the paper, and it is recommended this
    /// section be read in consultation with the paper. We note that since
    /// each polynomial is being evaluated at all of the points,
    ///     Z_{T\S_i} = Z_{{}} = 1.
    ///
    /// It is a logic error for:
    ///  - `poly.len() != z.len()`
    ///  - the values in `v` to be incorrect.
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> Self::Proof {
        //Corresponds to `f` from the paper.
        let mut f = vec![E::ScalarField::ZERO; poly[0].degree()+1];
        //Corresponds to `L` from the paper.
        let mut L = vec![E::ScalarField::ZERO; poly[0].degree()+1];

        //Retains the value of \lambda^{i-1} in the loop, to minimise multiplications.
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

        // ztVec is an auxiliary data structure used to calculate
        //      Z_T := \prod_{t \in T} (X - t)
        // This definition can be found in the paper. In this function `z` is `T`.
        //
        // The straightforward means of evaluation (multiplying all (X-t) together)
        // incurs a runtime cost of O(n^2 log(n)). It is better to evaluate it
        // in the following fashion:
        //
        // (X - t_1)    (X - t_2)    (X - t_3)    (X - t_4)
        // (X - t_1)(X - t_2)    (X - t_3)(X - t_4)
        // (X - t_1)(X - t_2)(X - t_3)(X - t_4)
        //
        // This is to say, we put all of the linear polynomials on the base level,
        // and then we combine neighbours together until we are left with one element.
        // This gives a runtime of O(n log(n)) per level, yielding the much better
        // O(n log^2(n)) complexity for calculation overall.
        let mut ztVec: Vec<DensePolynomial<E::ScalarField>> = z.iter().map(|v| DensePolynomial::from_coefficients_slice(&[v.neg(), E::ScalarField::ONE])).collect();
        let mut accum = 2;
        for i in 0..z.len().ilog2() {
            for j in 0..(z.len()/accum) {
                ztVec[j] = ztVec[2*j].clone() * ztVec[2*j+1].clone();
            }
            accum *= 2;
        }

        // zt is defined as above.
        let zt = ztVec[0].clone();


        let mut w_partial = DensePolynomial::from_coefficients_vec(f) / zt.clone();

        let W = eval_poly_over_g1::<E>(&w_partial, &pk.g1);

        w_partial = w_partial * zt.evaluate(&ver_params.1);

        for (j, c) in w_partial.coeffs().iter().enumerate() {
            L[j] -= c;
        }

        let mut L = DensePolynomial::from_coefficients_vec(L);

        L = L / DensePolynomial::from_coefficients_slice(&[ver_params.1.neg(), E::ScalarField::ONE]);

        let Wp = eval_poly_over_g1::<E>(&L, &pk.g1);
        
        (W, Wp)
    }

    /// Verifies that the proof `p` is valid for the given parameters, and returns true
    /// if it is, and false if it is not.
    ///
    /// The calculations carried out below are faithful to the equations
    /// presented in section 4.1 of the paper, and it is recommended this
    /// section be read in consultation with the paper. We note that since
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> bool {
        let (W, Wp) = *p;

        let mut F = E::G1::ZERO;

        let mut mid = E::ScalarField::ZERO;

        //Retains the value of \lambda^{i-1} in the loop, to minimise multiplications.
        let mut accum = E::ScalarField::ONE;
        for (i, comm) in c.iter().enumerate() {
            F += comm.mul(accum);
            mid += accum * v[i].evaluate(&ver_params.1);

            accum *= ver_params.0;
        }

        F = F - pk.g1[0].mul(mid);

        // See `open` for an explanation of the calculation below.
        let mut ztVec: Vec<DensePolynomial<E::ScalarField>> = z.iter().map(|v| DensePolynomial::from_coefficients_slice(&[v.neg(), E::ScalarField::ONE])).collect();
        let mut accum = 2;
        for i in 0..z.len().ilog2() {
            for j in 0..(z.len()/accum) {
                ztVec[j] = ztVec[2*j].clone() * ztVec[2*j+1].clone();
            }
            accum *= 2;
        }

        // zt is defined as above.
        let zt = ztVec[0].clone();

        F -= W.mul(zt.evaluate(&ver_params.1));


        let lhs = E::pairing(F + Wp.mul(ver_params.1), pk.g2_one);
        let rhs = E::pairing(Wp, pk.g2_x);

        lhs == rhs
    }
}
