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

use ark_std::test_rng;
use proof_of_sql::{
    base::commitment::QueryCommitments,
    base::{
        commitment::{Commitment, CommitmentEvaluationProof, QueryCommitmentsExt},
        database::CommitmentAccessor,
        database::{owned_table_utility::*, OwnedTableTestAccessor, SchemaAccessor, TestAccessor},
    },
    proof_primitive::dory::{
        DoryEvaluationProof, DoryProverPublicSetup, ProverSetup, PublicParameters,
    },
    sql::{
        parse::QueryExpr,
        proof::{ProofPlan, VerifiableQueryResult},
    },
};

use proof_of_sql_verifier::{Proof, PublicInput, VerificationKey};

// Helper functions for setting up test data and queries

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

/// Builds a test accessor with altered sample data.
fn build_altered_accessor<T: CommitmentEvaluationProof>(
    setup: <T as CommitmentEvaluationProof>::ProverPublicSetup<'_>,
) -> OwnedTableTestAccessor<T> {
    let mut accessor = OwnedTableTestAccessor::<T>::new_empty_with_setup(setup);
    accessor.add_table(
        "sxt.table".parse().unwrap(),
        owned_table([
            bigint("a", [1, 2, 3, 2]),
            varchar("b", ["hi", "hello", "there", "zkVerify"]),
        ]),
        0,
    );
    accessor
}

/// Builds a test accessor with different table and column names.
fn build_alien_accessor<T: CommitmentEvaluationProof>(
    setup: <T as CommitmentEvaluationProof>::ProverPublicSetup<'_>,
) -> OwnedTableTestAccessor<T> {
    let mut accessor = OwnedTableTestAccessor::<T>::new_empty_with_setup(setup);
    accessor.add_table(
        "sxt.table2".parse().unwrap(),
        owned_table([
            bigint("c", [1, 2, 3, 2]),
            varchar("d", ["hi", "hello", "there", "world"]),
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

/// Builds a sample query for the "alien" accessor.
fn build_alien_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
    QueryExpr::try_new(
        "SELECT d FROM table2 WHERE c = 2".parse().unwrap(),
        "sxt".parse().unwrap(),
        accessor,
    )
    .unwrap()
}

/// Builds a query for a non-existent record.
fn build_query_non_existant_record<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
    QueryExpr::try_new(
        "SELECT b FROM table WHERE a = 4".parse().unwrap(),
        "sxt".parse().unwrap(),
        accessor,
    )
    .unwrap()
}

mod generate_and_verify_proof {
    use proof_of_sql::proof_primitive::dory::{DoryVerifierPublicSetup, VerifierSetup};

    use super::*;

    /// Tests the generation and verification of a Dory proof.
    #[test]
    fn base() {
        // Initialize setup
        let max_nu = 4;
        let sigma = max_nu;
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, sigma);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, sigma);

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
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        // Verify proof
        let query_commitments = compute_query_commitments(&query, &accessor);
        let proof = Proof::new(proof);
        let pubs = PublicInput::new(query.proof_expr(), query_commitments, query_data);
        let vk = VerificationKey::new(&public_parameters, sigma);
        let result = proof_of_sql_verifier::verify_proof(&proof, &pubs, &vk);

        assert!(result.is_ok());
    }

    /// Tests the generation and verification of a Dory proof for a non-existent record.
    #[test]
    fn for_non_existant_record() {
        // Initialize setup
        let max_nu = 4;
        let sigma = max_nu;
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, sigma);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, sigma);

        // Build table accessor and query
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let non_existant_query = build_query_non_existant_record(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            non_existant_query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        // Get query data
        let query_data = proof
            .verify(non_existant_query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        let query_commitments = compute_query_commitments(&non_existant_query, &accessor);
        let dory_proof = Proof::new(proof);
        let pubs = PublicInput::new(
            non_existant_query.proof_expr(),
            query_commitments,
            query_data,
        );
        let vk = VerificationKey::new(&public_parameters, sigma);
        let result = proof_of_sql_verifier::verify_proof(&dory_proof, &pubs, &vk);

        assert!(result.is_ok());
    }

    /// Tests that verification fails when commitments are missing.
    #[test]
    fn without_commitments() {
        // Initialize setup
        let max_nu = 4;
        let sigma = max_nu;
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, sigma);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, sigma);

        // Build table accessor and query
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let query = build_query(&accessor);

        // Generate proof
        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        // Get query data
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        let no_commitments = QueryCommitments::default();
        let proof = Proof::new(proof);
        let pubs = PublicInput::new(query.proof_expr(), no_commitments, query_data);
        let vk = VerificationKey::new(&public_parameters, 4);
        let result = proof_of_sql_verifier::verify_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }

    /// Tests that verification fails when the underlying data has been altered.
    #[test]
    fn for_altered_data() {
        // Initialize setup
        let max_nu = 4;
        let sigma = max_nu;
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, sigma);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, sigma);

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
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        // Alter the data
        let altered_accessor: OwnedTableTestAccessor<DoryEvaluationProof> =
            build_altered_accessor(prover_setup);

        // Verify proof
        let altered_query_commitments = compute_query_commitments(&query, &altered_accessor);
        let proof = Proof::new(proof);
        let pubs = PublicInput::new(query.proof_expr(), altered_query_commitments, query_data);
        let vk = VerificationKey::new(&public_parameters, sigma);
        let result = proof_of_sql_verifier::verify_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }

    /// Tests that verification fails when using commitments from a different accessor.
    #[test]
    fn from_alien_accessor() {
        // Initialize setup
        let max_nu = 4;
        let sigma = max_nu;
        let public_parameters = PublicParameters::test_rand(max_nu, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, sigma);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, sigma);

        // Build table accessors and queries
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let alien_accessor = build_alien_accessor::<DoryEvaluationProof>(prover_setup);
        let query = build_query(&accessor);
        let alien_query = build_alien_query(&alien_accessor);

        // Generate proof for original accessor and query
        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        // Get the result
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        // Compute query commitments for alien accessor
        let query_commitments = compute_query_commitments(&alien_query, &alien_accessor);
        let proof = Proof::new(proof);
        let pubs = PublicInput::new(query.proof_expr(), query_commitments, query_data);
        let vk = VerificationKey::new(&public_parameters, sigma);
        let result = proof_of_sql_verifier::verify_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }
}
