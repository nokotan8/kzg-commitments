use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

pub trait PolyCommit<E: Pairing, PK, SK, Commitment, Proof> {
    fn new() -> Self;
    fn setup(&mut self, max_deg: i32) -> (PK, SK); // throw away SK
    fn commit(&self, pk: &PK, poly: &DensePolynomial<E::ScalarField>) -> Commitment;
    // first poly first z is first v, first poly second z is second v, ... second poly first z is (t+1)th v
    fn open(&self, pk: &PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[E::ScalarField]) -> Proof;
    fn verify(&self, c: &[Commitment], pk: &PK, p: &Proof, z: &[E::ScalarField], v: &[E::ScalarField]) -> bool;
}