use proof_of_sql::{
    base::commitment::QueryCommitments,
    sql::{
        ast::ProofPlan,
        proof::{QueryData, VerifiableQueryResult},
    },
};

pub use proof_of_sql::proof_primitive::dory::{
    DoryCommitment, DoryEvaluationProof, DoryScalar, DoryVerifierPublicSetup,
};

use crate::{error::VerifyError, verify_generic::verify_proof};

pub fn verify_dory_proof(
    proof: VerifiableQueryResult<DoryEvaluationProof>,
    expr: &ProofPlan<DoryCommitment>,
    commitments: &QueryCommitments<DoryCommitment>,
    query_data: &QueryData<DoryScalar>,
    setup: &DoryVerifierPublicSetup<'_>,
) -> Result<(), VerifyError> {
    verify_proof(proof, expr, commitments, query_data, setup)
}
