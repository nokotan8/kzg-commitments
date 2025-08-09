use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;

/// Generic trait which implements the interface for a batched polynomial commitment.
/// Instances of the class should be instantiated by the prover, and the verifier only
/// needs to use the `verify` function.
///
/// Importantly for our applications, the number of polynomials committed to and the number
/// of points must be the same. Providing a differing number of polynomials and points is
/// considered a logic error. Additionally, the degrees of the polynomials, as well
/// as the number of points and polynomials committed to, must be powers of 2. It is
/// a logic error for this to not be the case.
///
pub trait PolyCommit<E: Pairing> {
    /// Public key
    type PK;
    /// Secret key. For our applications this value can be safely discarded.
    type SK;
    /// Commitment to a collection of polynomials.
    type Commitment;
    /// Values of the collection of polynomial over some set of points.
    /// It is important to note that these values are not necessarily lists of values:
    /// in some cases it is more expedient to return a polynomial of low degree
    /// which agrees with the polynomial for all the given values.
    type Evaluation;
    /// Proofs of the evaluations of a collection of polynomials over a set of points.
    type Proof;
    /// Some procedures require the verifier to provide random arguments. These arguments
    /// are packaged into this type.
    type VerifierParams;

    fn new() -> Self;

    /// Initialises the polynomial commit for polynomial up to degreee `max_deg`.
    fn setup(&mut self, max_deg: usize) -> (Self::PK, Self::SK); // throw away SK

    /// Using the public key parameters `pk`, this function commits to all of the polynomials
    /// in `poly` and returns the commitment.
    fn commit(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>]) -> Self::Commitment;

    /// Evaluates the given polynomials in `poly` at each of the points in `z`, and returns the
    /// values. Importantly, the length of `poly` must match the length of `z`: it is a logic
    /// error for this not to be the case.
    fn evaluate(&self, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField]) -> Vec<Self::Evaluation>;

    /// Creates witness for all of the polynomials in `poly` evaluated at all of the points in `z`.
    /// As above, it is a logic error for the length of `poly` to not be the same as the length of
    /// `z`.
    /// This function will assume that the values in `v` are accurate.
    fn open(&self, pk: &Self::PK, poly: &[DensePolynomial<E::ScalarField>], z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> Self::Proof;

    /// Verifies, given the commitments to the polynomials in `c`, that the proofs in `p` are valid
    /// for the points in `z`. Returns true if the proofs are valid, and false if not.
    fn verify(c: &Self::Commitment, pk: &Self::PK, p: &Self::Proof, z: &[E::ScalarField], v: &[Self::Evaluation], ver_params: &Self::VerifierParams) -> bool;
}
