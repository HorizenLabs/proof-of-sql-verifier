// Copyright 2024, Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use proof_of_sql::base::commitment::CommitmentEvaluationProof;
use proof_of_sql::sql::proof::ProofPlan;
use proof_of_sql::sql::proof_plans::DynProofPlan;
use proof_of_sql::{
    base::commitment::QueryCommitments,
    sql::proof::{QueryData, VerifiableQueryResult},
};

use crate::{Proof, PublicInput, VerificationKey, VerifyError};

/// Verifies a generic proof against the provided expression, commitments, and query data.
///
/// # Type Parameters
///
/// * `CP` - A type that implements `CommitmentEvaluationProof`.
///
/// # Arguments
///
/// * `proof` - The proof to be verified, wrapped in a `VerifiableQueryResult`.
/// * `expr` - The proof plan expression.
/// * `commitments` - The query commitments.
/// * `query_data` - The query data.
/// * `setup` - The verifier's public setup.
///
/// # Returns
///
/// * `Result<(), VerifyError>` - Ok(()) if the proof is valid, or an error if verification fails.
pub fn verify_proof_internal<CP: CommitmentEvaluationProof>(
    proof: VerifiableQueryResult<CP>,
    expr: &DynProofPlan<CP::Commitment>,
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
                    return Err(VerifyError::InvalidInput);
                }
            }
        } else {
            return Err(VerifyError::InvalidInput);
        }
    }

    let result = proof
        .verify(expr, commitments, setup)
        .map_err(|_| VerifyError::VerificationFailed)?;

    if result.table != query_data.table || result.verification_hash != query_data.verification_hash
    {
        Err(VerifyError::VerificationFailed)
    } else {
        Ok(())
    }
}

/// Verifies a Dory proof against the provided public input and verification key.
///
/// # Arguments
///
/// * `proof` - The Dory proof to be verified.
/// * `pubs` - The public input for the proof.
/// * `vk` - The verification key used to verify the proof.
///
/// # Type Parameters
///
/// * `N` - A const generic parameter, likely related to the size of the verification key.
///
/// # Returns
///
/// * `Result<(), VerifyError>` - Ok(()) if the proof is valid, or an error if verification fails.
pub fn verify_proof(
    proof: &Proof,
    pubs: &PublicInput,
    vk: &VerificationKey,
) -> Result<(), VerifyError> {
    verify_proof_internal(
        proof.clone().into_dory(),
        pubs.expr(),
        pubs.commitments(),
        pubs.query_data(),
        &vk.into_dory(),
    )
}
