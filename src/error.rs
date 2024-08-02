#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// Provided data has not valid public inputs.
    InvalidInput,
    /// Provided data has not valid proof.
    InvalidProofData,
    /// Verify proof failed.
    VerifyError,
    /// Provided an invalid verification key.
    InvalidVerificationKey,
}
