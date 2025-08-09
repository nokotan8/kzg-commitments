use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::{marker::PhantomData, ops::Mul};
use crate::utils::poly::eval_poly_over_g1;

/// Struct for implementing the polynomial commitment scheme described in
/// [this paper](https://eprint.iacr.org/2019/953.pdf).
pub struct GWC19<E: Pairing> {
    max_deg: usize,
    _phantom: PhantomData<E>
}

pub struct GWC_PK<E: Pairing> {
    /// Corresponds to <g_1, g_1^a, g_1^{a^2}, .... , g_1^{a^t}>
    pub g1_vec: Vec<E::G1>,
    /// Corresponds to g_2
    pub g2_1: E::G2,
    /// Corresponds to g_2^a
    pub g2_x: E::G2
}

/// Implementation of batched polynomial commitments for GWC19
impl <E: Pairing> PolyCommit<E> for GWC19<E> {
    type PK = GWC_PK<E>;
    type SK = E::ScalarField;
    /// The commitment consists of 1 element of G_1 for each polynomial
    /// committed to.
    type Commitment = Vec<E::G1>;
    /// List of the values of a polynomial at each input point.
    type Evaluation = Vec<E::ScalarField>;
    /// We provide a proof element in G_1 for each point.
    type Proof = Vec<E::G1>;
    /// The verifier must send one element of Z_p per point.
    type VerifierParams = Vec<E::ScalarField>;

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
        for i in 0..=max_deg {
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
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> Self::Proof {
        let mut proofs = vec![];
        for i in 0..z.len() {
            let mut h = DensePolynomial { coeffs: vec![E::ScalarField::zero()] };
            for j in 0..poly.len() {
                let f_x = &poly[j];
                let f_z = v[j][i];
                let (quot, _rem) = DenseOrSparsePolynomial::from(f_x - DensePolynomial::from_coefficients_slice(&[f_z])).divide_with_q_and_r(&DenseOrSparsePolynomial::from(DensePolynomial::from_coefficients_slice(&[-z[i], E::ScalarField::ONE]))).unwrap();
                h = h + quot * ver_params[i].pow(&[j as u64]);
            }

            proofs.push(eval_poly_over_g1::<E>(&h, &pk.g1_vec));
        }

        if proofs.len() != z.len() {
            panic!("Opening/proof witness creation failed!");
        }

        proofs
    }

    /// Verifies that the proof `p` is valid for the given parameters, and
    /// returns true if it is, and false if it is not.
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> bool {
        let mut rng = test_rng();
        let num_r = z.len();
        let mut r = vec![];
        for _ in 0..num_r {
            r.push(E::ScalarField::rand(&mut rng));
        }
        r[0] = E::ScalarField::ONE;

        // there are poly.len() many commitments
        // there are z.len() many witnesses
        // there are poly.len() many gamma

        let mut f = E::G1::zero();
        for i in 0..r.len() {
            let mut g = E::G1::zero();
            for j in 0..c.len() {
                g += c[j].mul(ver_params[i].pow(&[j as u64]));
            }
            let mut h = E::ScalarField::zero();
            for j in 0..c.len() {
                h += v[j][i] * ver_params[i].pow(&[j as u64]);
            }
            f += (g - pk.g1_vec[0].mul(h)).mul(r[i]);
        }
        
        let mut lhs_1 = f;
        for i in 0..r.len() {
            lhs_1 += p[i].mul(z[i] * r[i]);
        }

        let mut rhs_1 = E::G1::zero();
        for i in 0..r.len() {
            rhs_1 += p[i].mul(r[i]);
        }

        let lhs = E::pairing(lhs_1, pk.g2_1);
        let rhs = E::pairing(rhs_1, pk.g2_x);

        println!("{:?}", lhs);
        println!("{:?}", rhs);

        lhs == rhs
    }
}

