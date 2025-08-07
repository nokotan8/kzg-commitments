use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

pub trait PolyCommit<E: Pairing> {
    type PK;
    type SK;
    type Commitment;
    // Evaluation represents the evaluation of one polynomial at a bunch of points.
    type Evaluation;
    type Proof;
    type VerifierParams;

    fn new() -> Self;

    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK); // throw away SK

    fn commit(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment;

    // Evaluation represents the evaluation of one polynomial at a bunch of points.
    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation>;

    // first poly first z is first v, first poly second z is second v, ... second poly first z is (t+1)th v
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: Self::VerifierParams) -> Self::Proof;

    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation]) -> bool;
}