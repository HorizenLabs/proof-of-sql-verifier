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
    proof_primitive::dory::{DoryCommitment, DoryScalar},
    sql::{ast::ProofPlan, parse::QueryExpr, proof::QueryData},
};

/// Represents the public input for a Dory proof.
///
/// This structure encapsulates the necessary public information required
/// for verifying a Dory proof, including the proof expression, commitments,
/// and query data.
///
/// # Type Parameters
///
/// * `'a` - The lifetime of the referenced `ProofPlan`.
pub struct DoryPublicInput<'a> {
    expr: &'a ProofPlan<DoryCommitment>,
    commitments: QueryCommitments<DoryCommitment>,
    query_data: QueryData<DoryScalar>,
}

impl<'a> DoryPublicInput<'a> {
    /// Creates a new `DoryPublicInput` instance.
    ///
    /// # Arguments
    ///
    /// * `query_expr` - A reference to the query expression.
    /// * `commitments` - The query commitments.
    /// * `query_data` - The query data.
    ///
    /// # Returns
    ///
    /// A new `DoryPublicInput` instance.
    pub fn new(
        query_expr: &'a QueryExpr<DoryCommitment>,
        commitments: QueryCommitments<DoryCommitment>,
        query_data: QueryData<DoryScalar>,
    ) -> Self {
        Self {
            expr: query_expr.proof_expr(),
            commitments,
            query_data,
        }
    }

    /// Returns a reference to the proof expression.
    pub fn expr(&self) -> &ProofPlan<DoryCommitment> {
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
}
