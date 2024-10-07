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

use std::fs::File;
use std::io::prelude::*;

use proof_of_sql::base::commitment::QueryCommitments;
use proof_of_sql::proof_primitive::dory::{
    DoryEvaluationProof, DoryProverPublicSetup, ProverSetup, PublicParameters,
};
pub use proof_of_sql::{
    base::{
        commitment::{Commitment, CommitmentEvaluationProof, QueryCommitmentsExt},
        database::{owned_table_utility::*, OwnedTableTestAccessor, SchemaAccessor, TestAccessor},
    },
    sql::{
        parse::QueryExpr,
        proof::{ProofPlan, VerifiableQueryResult},
    },
};
use proof_of_sql_verifier::{DoryProof, DoryPublicInput, VerificationKey};
use rand::thread_rng;

fn main() {
    // Initialize setup
    let public_parameters = PublicParameters::rand(4, &mut thread_rng());
    let ps = ProverSetup::from(&public_parameters);
    let prover_setup = DoryProverPublicSetup::new(&ps, 4);

    // Build table accessor and query
    let mut accessor =
        OwnedTableTestAccessor::<DoryEvaluationProof>::new_empty_with_setup(prover_setup);
    accessor.add_table(
        "sxt.table".parse().unwrap(),
        owned_table([
            bigint("a", [1, 2, 3, 2]),
            varchar("b", ["hi", "hello", "there", "world"]),
        ]),
        0,
    );

    let query = QueryExpr::try_new(
        "SELECT b FROM table WHERE a = 2".parse().unwrap(),
        "sxt".parse().unwrap(),
        &accessor,
    )
    .unwrap();

    // Generate proof
    let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
        query.proof_expr(),
        &accessor,
        &prover_setup,
    );

    // Get query data and commitments
    let vk = VerificationKey::new(&public_parameters, 4);
    let query_data = proof
        .verify(query.proof_expr(), &accessor, &vk.into_dory())
        .unwrap();

    let columns = query.proof_expr().get_column_references();
    let query_commitments = QueryCommitments::from_accessor_with_max_bounds(columns, &accessor);

    // Verify proof
    let proof = DoryProof::new(proof);
    let pubs = DoryPublicInput::new(query.proof_expr(), query_commitments, query_data.into());
    let _result = proof_of_sql_verifier::verify_dory_proof(&proof, &pubs, &vk);

    // Write proof, pubs, and vk to binary files
    let mut proof_bin = File::create("proof.bin").unwrap();
    proof_bin.write_all(&proof.into_bytes()).unwrap();
    let mut pubs_bin = File::create("pubs.bin").unwrap();
    pubs_bin.write_all(&pubs.into_bytes().unwrap()).unwrap();
    let mut vk_bin = File::create("vk.bin").unwrap();
    vk_bin.write_all(&vk.into_bytes()).unwrap();
}
