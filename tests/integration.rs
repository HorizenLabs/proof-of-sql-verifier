pub mod common {
    pub use proof_of_sql::{
        base::{
            commitment::{Commitment, CommitmentEvaluationProof},
            database::{
                owned_table_utility::*, OwnedTableTestAccessor, SchemaAccessor, TestAccessor,
            },
        },
        sql::{parse::QueryExpr, proof::VerifiableQueryResult},
    };

    pub fn build_accessor<T: CommitmentEvaluationProof>(
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

    pub fn build_altered_accessor<T: CommitmentEvaluationProof>(
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

    pub fn build_alien_accessor<T: CommitmentEvaluationProof>(
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

    pub fn build_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
        QueryExpr::try_new(
            "SELECT b FROM table WHERE a = 2".parse().unwrap(),
            "sxt".parse().unwrap(),
            accessor,
        )
        .unwrap()
    }

    pub fn build_alien_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
        QueryExpr::try_new(
            "SELECT d FROM table2 WHERE c = 2".parse().unwrap(),
            "sxt".parse().unwrap(),
            accessor,
        )
        .unwrap()
    }

    pub fn build_query_non_existant_record<T: Commitment>(
        accessor: &impl SchemaAccessor,
    ) -> QueryExpr<T> {
        QueryExpr::try_new(
            "SELECT b FROM table WHERE a = 4".parse().unwrap(),
            "sxt".parse().unwrap(),
            accessor,
        )
        .unwrap()
    }
}

#[cfg(feature = "inner-product")]
mod inner_product {
    use super::common::*;

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
        let query_commitments = proof_of_sql_verifier::compute_query_commitments(&query, &accessor);

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

    use super::common::*;

    use proof_of_sql::proof_primitive::dory::{
        test_rng, DoryEvaluationProof, DoryProverPublicSetup, DoryVerifierPublicSetup, ProverSetup,
        PublicParameters, VerifierSetup,
    };

    use proof_of_sql::base::commitment::QueryCommitments;

    #[test]
    fn generate_and_verify_proof() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

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
        let query_commitments = proof_of_sql_verifier::compute_query_commitments(&query, &accessor);

        // Verify proof
        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            query.proof_expr(),
            &query_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn generate_and_verify_proof_for_non_existant_record() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

        // Build table accessor and query
        let accessor = build_accessor::<DoryEvaluationProof>(prover_setup);
        let non_existant_query = build_query_non_existant_record(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            non_existant_query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(non_existant_query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();
        let query_commitments =
            proof_of_sql_verifier::compute_query_commitments(&non_existant_query, &accessor);

        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            non_existant_query.proof_expr(),
            &query_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn generate_and_verify_proof_without_commitments() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

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
        let no_commitments = QueryCommitments::new();

        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            query.proof_expr(),
            &no_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_err());
    }

    #[test]
    fn generate_and_verify_proof_for_altered_data() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

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
        let altered_query_commitments =
            proof_of_sql_verifier::compute_query_commitments(&query, &altered_accessor);

        // Verify proof
        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            query.proof_expr(),
            &altered_query_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_err());
    }

    #[test]
    fn generate_and_verify_proof_from_alien_accessor() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

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
        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        // Compute query commitments for alien accessor
        let query_commitments =
            proof_of_sql_verifier::compute_query_commitments(&alient_query, &alien_accessor);

        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            query.proof_expr(),
            &query_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_err());
    }
}
