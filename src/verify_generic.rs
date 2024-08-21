// Copyright 2024, The Horizen Foundation
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
use proof_of_sql::sql::proof::ProofExpr;
use proof_of_sql::{
    base::commitment::QueryCommitments,
    sql::{
        ast::ProofPlan,
        proof::{QueryData, VerifiableQueryResult},
    },
};

use crate::VerifyError;

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
