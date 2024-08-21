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

use proof_of_sql::base::{commitment::QueryCommitments, database::CommitmentAccessor};
pub use proof_of_sql::{
    base::{
        commitment::{Commitment, CommitmentEvaluationProof, QueryCommitmentsExt},
        database::{owned_table_utility::*, OwnedTableTestAccessor, SchemaAccessor, TestAccessor},
    },
    sql::{parse::QueryExpr, proof::ProofExpr, proof::VerifiableQueryResult},
};

fn compute_query_commitments<C: Commitment>(
    query_expr: &QueryExpr<C>,
    accessor: &(impl CommitmentAccessor<C> + SchemaAccessor),
) -> QueryCommitments<C> {
    let columns = query_expr.proof_expr().get_column_references();
    QueryCommitments::from_accessor_with_max_bounds(columns, accessor)
}

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

fn build_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
    QueryExpr::try_new(
        "SELECT b FROM table WHERE a = 2".parse().unwrap(),
        "sxt".parse().unwrap(),
        accessor,
    )
    .unwrap()
}

fn build_alien_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
    QueryExpr::try_new(
        "SELECT d FROM table2 WHERE c = 2".parse().unwrap(),
        "sxt".parse().unwrap(),
        accessor,
    )
    .unwrap()
}

fn build_query_non_existant_record<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
    QueryExpr::try_new(
        "SELECT b FROM table WHERE a = 4".parse().unwrap(),
        "sxt".parse().unwrap(),
        accessor,
    )
    .unwrap()
}

#[cfg(feature = "inner-product")]
mod inner_product {
    use super::*;

    use blitzar::{self, proof::InnerProductProof};

    #[test]
    fn generate_and_verify_proof() {
        blitzar::compute::init_backend();

        let prover_setup = ();
        let verifier_setup = ();

        let accessor: OwnedTableTestAccessor<InnerProductProof> = build_accessor(prover_setup);
        let query = build_query(&accessor);

        let proof = VerifiableQueryResult::<InnerProductProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();
        let query_commitments = compute_query_commitments(&query, &accessor);

        let result = proof_of_sql_verifier::verify_inner_product_proof(
            proof,
            query.proof_expr(),
            &query_commitments,
            &query_data,
        );

        assert!(result.is_ok());
    }
}

mod dory {

    use super::*;

    use proof_of_sql::proof_primitive::dory::{
        test_rng, DoryEvaluationProof, DoryProverPublicSetup, ProverSetup, PublicParameters,
    };

    use proof_of_sql::base::commitment::QueryCommitments;
    use proof_of_sql_verifier::{DoryProof, DoryPublicInput, VerificationKey};

    #[test]
    fn generate_and_verify_proof() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);

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
        let vk = VerificationKey::<4>::new(&public_parameters);
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();
        let query_commitments = compute_query_commitments(&query, &accessor);

        // Verify proof
        let proof = DoryProof::new(proof);
        let pubs = DoryPublicInput::new(&query, query_commitments, query_data);
        let result = proof_of_sql_verifier::verify_dory_proof(&proof, &pubs, &vk);

        assert!(result.is_ok());
    }

    #[test]
    fn generate_and_verify_proof_for_non_existant_record() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);

        // Build table accessor and query
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let non_existant_query = build_query_non_existant_record(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            non_existant_query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let vk = VerificationKey::<4>::new(&public_parameters);

        let query_data = proof
            .verify(non_existant_query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();
        let query_commitments = compute_query_commitments(&non_existant_query, &accessor);

        let dory_proof = DoryProof::new(proof);
        let pubs = DoryPublicInput::new(&non_existant_query, query_commitments, query_data);
        let result = proof_of_sql_verifier::verify_dory_proof(&dory_proof, &pubs, &vk);

        assert!(result.is_ok());
    }

    #[test]
    fn generate_and_verify_proof_without_commitments() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);

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
        let vk = VerificationKey::<4>::new(&public_parameters);
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();
        let no_commitments = QueryCommitments::new();

        let proof = DoryProof::new(proof);
        let pubs = DoryPublicInput::new(&query, no_commitments, query_data);
        let result = proof_of_sql_verifier::verify_dory_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }

    #[test]
    fn generate_and_verify_proof_for_altered_data() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);

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
        let vk = VerificationKey::<4>::new(&public_parameters);
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();

        // Alter the data
        let altered_accessor: OwnedTableTestAccessor<DoryEvaluationProof> =
            build_altered_accessor(prover_setup);
        let altered_query_commitments = compute_query_commitments(&query, &altered_accessor);

        // Verify proof
        let proof = DoryProof::new(proof);
        let pubs = DoryPublicInput::new(&query, altered_query_commitments, query_data);
        let result = proof_of_sql_verifier::verify_dory_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }

    #[test]
    fn generate_and_verify_proof_from_alien_accessor() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);

        // Build table accessors and queries
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let alien_accessor = build_alien_accessor::<DoryEvaluationProof>(prover_setup);
        let query = build_query(&accessor);
        let alient_query = build_alien_query(&alien_accessor);

        // Generate proof for original accessor and query
        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        // Get the result
        let vk = VerificationKey::<4>::new(&public_parameters);
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();

        // Compute query commitments for alien accessor
        let query_commitments = compute_query_commitments(&alient_query, &alien_accessor);

        let proof = DoryProof::new(proof);
        let pubs = DoryPublicInput::new(&query, query_commitments, query_data);
        let result = proof_of_sql_verifier::verify_dory_proof(&proof, &pubs, &vk);

        assert!(result.is_err());
    }
}
