use proof_of_sql::base::commitment::CommitmentEvaluationProof;
use proof_of_sql::sql::proof::ProofExpr;

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
    // Check that the columns in the proof match the columns in the commitments
    for column in expr.get_column_references() {
        if let Some(commitment) = commitments.get(&column.table_ref()) {
            if let Some(metadata) = commitment
                .column_commitments()
                .get_metadata(&column.column_id())
            {
                if metadata.column_type() != column.column_type() {
                    return Err(VerifyError::VerifyError);
                }
            }
        } else {
            return Err(VerifyError::VerifyError);
        }
    }

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
