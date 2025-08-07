use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
pub trait PolyCommit<E: Pairing, PK, SK, Commitment, Proof> {
    fn setup(max_deg: i32) -> (PK, SK); // throw away SK
    fn commit(pk: PK, poly: DensePolynomial<E::ScalarField>) -> Commitment;
    fn open(pk: PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[E::ScalarField]) -> Proof;
    fn verify(c: &[Commitment], pk: PK, p: Proof, z: &[E::ScalarField], v: &[E::ScalarField]) -> bool;
}