use crate::poly_commit::{PolyCommit};
use ark_ff::{UniformRand, Field};
use ark_poly::{univariate::{DenseOrSparsePolynomial, DensePolynomial}, DenseUVPolynomial, Polynomial};
use ark_std::{test_rng, Zero};
use ark_ec::pairing::{Pairing};
use std::{marker::PhantomData, ops::Mul, panic};

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
    type VerifierParams = Vec<E::ScalarField>;

    fn new() -> Self {
        Self {
            max_deg: 0,
            _phantom: PhantomData
        }
    }

    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK) {
        let sk = E::ScalarField::rand(&mut test_rng());
        let g1 = E::G1::rand(&mut test_rng());
        let g2 = E::G2::rand(&mut test_rng());
        self.max_deg = max_deg;
        let g1_vec: Vec<E::G1> = (0..=max_deg).map(|i| g1.mul(sk.pow(&[i as u64]))).collect();
        (Self::PK {g1_vec: g1_vec, g2_1: g2, g2_x: g2.mul(sk)}, sk)
    }

    fn commit(&self, pk: &Self::PK, polynomials: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment {
        if polynomials.iter().any(|poly| poly.degree() > self.max_deg) {
            panic!("Polynomial exceeds maximum degree!");
        }
        let commitments: Self::Commitment = polynomials.iter().map(|polynomial| {
            pk.g1_vec.iter().zip(polynomial.iter()).fold(E::G1::zero(), |acc, (a, b)| acc + a.mul(b))
        }).collect();
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
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<<E as Pairing>::ScalarField>], z: &[<E as Pairing>::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> Self::Proof {
        let mut proofs = vec![];
        for i in 0..z.len() {
            let mut h = DensePolynomial { coeffs: vec![E::ScalarField::zero()] };
            for j in 0..poly.len() {
                let f_x = &poly[i];
                let f_z = DensePolynomial::from_coefficients_slice(&[v[j][i]]);
                let x_minus_z = DensePolynomial::from_coefficients_slice(&[-z[i], E::ScalarField::ONE]);
                let (quot, _rem) = DenseOrSparsePolynomial::from(f_x - f_z).divide_with_q_and_r(&DenseOrSparsePolynomial::from(x_minus_z)).unwrap();
                h = h + quot * ver_params[i].pow(&[j as u64]);
            }
        
            let mut c = E::G1::zero();
            for i in 0..h.degree() {
                c += pk.g1_vec[i].mul(h.coeffs[i]);
            }
            
            proofs.push(c);
        }

        if proofs.len() != z.len() {
            panic!("Opening/proof witness creation failed!");
        }

        proofs
    }

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

        // println!("{:?}", lhs);
        // println!("{:?}", rhs);

        lhs == rhs
    }
}

