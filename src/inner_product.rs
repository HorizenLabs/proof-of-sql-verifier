use proof_of_sql::{
    base::commitment::QueryCommitments,
    sql::{
        ast::ProofPlan,
        proof::{QueryData, VerifiableQueryResult},
    },
};

use crate::{error::VerifyError, verify_generic::verify_proof};

pub use blitzar::proof::InnerProductProof;
pub use curve25519_dalek::RistrettoPoint;
pub use proof_of_sql::base::scalar::Curve25519Scalar;

pub fn verify_inner_product_proof(
    proof: VerifiableQueryResult<InnerProductProof>,
    expr: &ProofPlan<RistrettoPoint>,
    commitments: &QueryCommitments<RistrettoPoint>,
    query_data: &QueryData<Curve25519Scalar>,
) -> Result<(), VerifyError> {
    verify_proof(proof, expr, commitments, query_data, &())
}
