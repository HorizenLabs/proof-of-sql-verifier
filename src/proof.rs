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

use proof_of_sql::proof_primitive::dory::DoryEvaluationProof;
use proof_of_sql::sql::proof::VerifiableQueryResult;

use crate::VerifyError;

/// Represents a Dory proof.
///
/// `DoryProof` is a wrapper around a `VerifiableQueryResult<DoryEvaluationProof>`.
/// It provides methods for creating, serializing, and deserializing Dory proofs.
///
/// # Fields
///
/// * `proof` - A `VerifiableQueryResult<DoryEvaluationProof>` containing the actual proof data.
#[derive(Clone)]
pub struct DoryProof {
    proof: VerifiableQueryResult<DoryEvaluationProof>,
}

impl TryFrom<&[u8]> for DoryProof {
    type Error = VerifyError;

    /// Attempts to create a DoryProof from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `value` - The byte slice containing the serialized proof.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Self::Error>` - A DoryProof if deserialization succeeds, or a VerifyError if it fails.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let proof = bincode::deserialize(value).map_err(|_| VerifyError::InvalidProofData)?;

        Ok(Self::new(proof))
    }
}

impl DoryProof {
    /// Creates a new DoryProof.
    ///
    /// # Arguments
    ///
    /// * `proof` - A VerifiableQueryResult containing a DoryEvaluationProof.
    ///
    /// # Returns
    ///
    /// * `Self` - A new DoryProof instance.
    pub fn new(proof: VerifiableQueryResult<DoryEvaluationProof>) -> Self {
        Self { proof }
    }

    /// Converts the DoryProof into a byte vector.
    ///
    /// # Returns
    ///
    /// * `Vec<u8>` - The serialized proof as a byte vector.
    pub fn into_bytes(self) -> Vec<u8> {
        bincode::serialize(&self.proof).unwrap()
    }

    /// Converts the DoryProof into a VerifiableQueryResult<DoryEvaluationProof>.
    ///
    /// # Returns
    ///
    /// * `VerifiableQueryResult<DoryEvaluationProof>` - The proof data.
    pub fn into_dory(self) -> VerifiableQueryResult<DoryEvaluationProof> {
        self.proof
    }
}
