use proof_of_sql::base::commitment::CommitmentEvaluationProof;

use crate::error::VerifyError;

pub use proof_of_sql::{
    base::commitment::QueryCommitments,
    sql::{
        ast::ProofPlan,
        proof::{QueryData, VerifiableQueryResult},
    },
};

pub fn verify_proof<CP: CommitmentEvaluationProof>(
    proof: VerifiableQueryResult<CP>,
    expr: &ProofPlan<CP::Commitment>,
    commitments: &QueryCommitments<CP::Commitment>,
    query_data: &QueryData<CP::Scalar>,
    setup: &CP::VerifierPublicSetup<'_>,
) -> Result<(), VerifyError> {
    // TODO check that the provided `commitments` contain all the necessary data.
    // This should be possible by replicating the same logic as
    // `proof_of_sql::base::commitment::query_commitments::QueryCommitments::from_accessor_with_max_bounds`
    // If this check is not done, then the `verify` method could panic if the accessor tries to access
    // data which does not exist inside teh `QueryCommitments` struct.
    let result = proof
        .verify(expr, commitments, setup)
        .map_err(|_| VerifyError::VerifyError)?;

    if result.table != query_data.table || result.verification_hash != query_data.verification_hash
    {
        Err(VerifyError::VerifyError)
    } else {
        Ok(())
    }
}
