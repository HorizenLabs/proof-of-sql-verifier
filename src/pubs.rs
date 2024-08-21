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

use proof_of_sql::{base::commitment::QueryCommitments, proof_primitive::dory::{DoryCommitment, DoryScalar}, sql::{ast::ProofPlan, parse::QueryExpr, proof::QueryData}};


pub struct DoryPublicInput<'a> {
    expr: &'a ProofPlan<DoryCommitment>,
    commitments: QueryCommitments<DoryCommitment>,
    query_data: QueryData<DoryScalar>,
}

impl<'a> DoryPublicInput<'a> {
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

    pub fn expr(&self) -> &ProofPlan<DoryCommitment> {
        &self.expr
    }

    pub fn commitments(&self) -> &QueryCommitments<DoryCommitment> {
        &self.commitments
    }

    pub fn query_data(&self) -> &QueryData<DoryScalar> {
        &self.query_data
    }
}