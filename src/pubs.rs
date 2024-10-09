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

use alloc::vec::Vec;
use proof_of_sql::{
    base::commitment::QueryCommitments,
    proof_primitive::dory::{DoryCommitment, DoryScalar},
    sql::{proof::QueryData, proof_plans::DynProofPlan},
};
use serde::{Deserialize, Serialize};

use crate::{serde::QueryDataDef, VerifyError};

/// Represents the public input for a Dory proof.
///
/// This structure encapsulates the necessary public information required
/// for verifying a Dory proof, including the proof expression, commitments,
/// and query data.
#[derive(Serialize, Deserialize)]
pub struct PublicInput {
    expr: DynProofPlan<DoryCommitment>,
    commitments: QueryCommitments<DoryCommitment>,
    #[serde(with = "QueryDataDef")]
    query_data: QueryData<DoryScalar>,
}

impl TryFrom<&[u8]> for PublicInput {
    type Error = VerifyError;

    fn try_from(bytes: &[u8]) -> Result<Self, VerifyError> {
        PublicInput::try_from_bytes(bytes).map_err(|_| VerifyError::InvalidInput)
    }
}

impl PublicInput {
    /// Creates a new `DoryPublicInput` instance.
    ///
    /// # Arguments
    ///
    /// * `expr` - The query plan for proving a query.
    /// * `commitments` - The query commitments.
    /// * `query_data` - The query data.
    ///
    /// # Returns
    ///
    /// A new `DoryPublicInput` instance.
    pub fn new(
        expr: &DynProofPlan<DoryCommitment>,
        commitments: QueryCommitments<DoryCommitment>,
        query_data: QueryData<DoryScalar>,
    ) -> Self {
        // Copy trait is not implemented for ProofPlan, so we serialize and deserialize
        let mut bytes = Vec::new();
        ciborium::into_writer(&expr, &mut bytes).unwrap();
        let expr: DynProofPlan<DoryCommitment> = ciborium::from_reader(&bytes[..]).unwrap();
        Self {
            expr,
            commitments,
            query_data,
        }
    }

    /// Returns a reference to the proof expression.
    pub fn expr(&self) -> &DynProofPlan<DoryCommitment> {
        &self.expr
    }

    /// Returns a reference to the query commitments.
    pub fn commitments(&self) -> &QueryCommitments<DoryCommitment> {
        &self.commitments
    }

    /// Returns a reference to the query data.
    pub fn query_data(&self) -> &QueryData<DoryScalar> {
        &self.query_data
    }

    /// Converts the public input into a byte array.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let mut result = Vec::new();
        ciborium::into_writer(self, &mut result).map_err(|_| VerifyError::InvalidInput)?;
        Ok(result)
    }

    /// Converts a byte array into a `DoryPublicInput` instance.
    fn try_from_bytes(bytes: &[u8]) -> Result<Self, VerifyError> {
        ciborium::from_reader(bytes).map_err(|_| VerifyError::InvalidInput)
    }
}

#[cfg(test)]
mod test {

    use ark_std::test_rng;
    use proof_of_sql::{
        base::{
            commitment::{Commitment, CommitmentEvaluationProof, QueryCommitmentsExt},
            database::{
                owned_table_utility::*, CommitmentAccessor, OwnedTableTestAccessor, SchemaAccessor,
                TestAccessor,
            },
        },
        proof_primitive::dory::{
            DoryEvaluationProof, DoryProverPublicSetup, ProverSetup, PublicParameters,
        },
        sql::{
            parse::QueryExpr,
            proof::{ProofPlan, VerifiableQueryResult},
        },
    };

    use crate::{Proof, VerificationKey};

    use super::*;

    /// Computes query commitments for a given query expression and accessor.
    fn compute_query_commitments<C: Commitment>(
        query_expr: &QueryExpr<C>,
        accessor: &(impl CommitmentAccessor<C> + SchemaAccessor),
    ) -> QueryCommitments<C> {
        let columns = query_expr.proof_expr().get_column_references();
        QueryCommitments::from_accessor_with_max_bounds(columns, accessor)
    }

    /// Builds a test accessor with sample data.
    fn build_accessor<T: CommitmentEvaluationProof>(
        setup: <T as CommitmentEvaluationProof>::ProverPublicSetup<'_>,
    ) -> OwnedTableTestAccessor<T> {
        let mut accessor = OwnedTableTestAccessor::<T>::new_empty_with_setup(setup);
        accessor.add_table(
            "sxt.table".parse().unwrap(),
            owned_table([
                bigint("a", [1, 2, 3, 2]),
                varchar("b", ["hi", "hello", "there", "world"]),
            ]),
            0,
        );
        accessor
    }

    /// Builds a sample query for testing.
    fn build_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
        QueryExpr::try_new(
            "SELECT b FROM table WHERE a = 2".parse().unwrap(),
            "sxt".parse().unwrap(),
            accessor,
        )
        .unwrap()
    }

    #[test]
    fn dory_public_input() {
        // Initialize setup
        let public_parameters = PublicParameters::test_rand(6, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let vk = VerificationKey::new(&public_parameters, 4);

        // Build table accessor and query
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let query = build_query(&accessor);

        // Generate proof
        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        // Get query data and commitments
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &vk.to_dory())
            .unwrap();
        let query_commitments = compute_query_commitments(&query, &accessor);

        // Verify proof
        let pubs = PublicInput::new(query.proof_expr(), query_commitments, query_data);

        let bytes = pubs.try_to_bytes().unwrap();

        let pubs = PublicInput::try_from(&bytes[..]).unwrap();
        let proof = Proof::new(proof);
        let result = crate::verify_proof(&proof, &pubs, &vk);

        assert!(result.is_ok());
    }
}
