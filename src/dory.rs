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

use crate::{error::VerifyError, verify_generic::verify_proof, VerificationKey};

pub fn verify_dory_proof<const N: usize>(
    proof: VerifiableQueryResult<DoryEvaluationProof>,
    expr: &ProofPlan<DoryCommitment>,
    commitments: &QueryCommitments<DoryCommitment>,
    query_data: &QueryData<DoryScalar>,
    vk: &VerificationKey<N>,
) -> Result<(), VerifyError> {
    verify_proof(proof, expr, commitments, query_data, &vk.into_dory())
}