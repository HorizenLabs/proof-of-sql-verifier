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

use proof_of_sql::proof_primitive::dory::DoryEvaluationProof;
use proof_of_sql::sql::proof::VerifiableQueryResult;

use crate::VerifyError;

#[derive(Clone)]
pub struct DoryProof {
    proof: VerifiableQueryResult<DoryEvaluationProof>,
}

impl TryFrom<&[u8]> for DoryProof {
    type Error = VerifyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let proof = bincode::deserialize(value).map_err(|_| VerifyError::InvalidProofData)?;

        Ok(Self::new(proof))
    }
}

impl Into<VerifiableQueryResult<DoryEvaluationProof>> for DoryProof {
    fn into(self) -> VerifiableQueryResult<DoryEvaluationProof> {
        self.proof
    }
}

impl DoryProof {
    pub fn new(proof: VerifiableQueryResult<DoryEvaluationProof>) -> Self {
        Self { proof }
    }
}
