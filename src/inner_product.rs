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

/// Verifies an inner product proof against the provided expression, commitments, and query data.
///
/// # Arguments
///
/// * `proof` - The inner product proof to be verified, wrapped in a VerifiableQueryResult.
/// * `expr` - The proof plan expression.
/// * `commitments` - The query commitments.
/// * `query_data` - The query data.
///
/// # Returns
///
/// * `Result<(), VerifyError>` - Ok(()) if the proof is valid, or an error if verification fails.
pub fn verify_inner_product_proof(
    proof: VerifiableQueryResult<InnerProductProof>,
    expr: &ProofPlan<RistrettoPoint>,
    commitments: &QueryCommitments<RistrettoPoint>,
    query_data: &QueryData<Curve25519Scalar>,
) -> Result<(), VerifyError> {
    verify_proof(proof, expr, commitments, query_data, &())
}
