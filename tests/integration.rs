#[cfg(any(feature = "inner-product", feature = "dory"))]
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

    pub fn build_alternative_accessor<T: CommitmentEvaluationProof>(
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

    pub fn build_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
        QueryExpr::try_new(
            "SELECT b FROM table WHERE a = 2".parse().unwrap(),
            "sxt".parse().unwrap(),
            accessor,
        )
        .unwrap()
    }

    pub fn build_missing_query<T: Commitment>(accessor: &impl SchemaAccessor) -> QueryExpr<T> {
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

#[cfg(feature = "dory")]
mod dory {

    use super::common::*;

    use proof_of_sql::proof_primitive::dory::{
        test_rng, DoryEvaluationProof, DoryProverPublicSetup, DoryVerifierPublicSetup, ProverSetup,
        PublicParameters, VerifierSetup,
    };

    use proof_of_sql::base::commitment::QueryCommitments;

    #[test]
    fn generate_and_verify_proof() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

        let accessor: OwnedTableTestAccessor<DoryEvaluationProof> = build_accessor(prover_setup);
        let query = build_query(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();
        let query_commitments = proof_of_sql_verifier::compute_query_commitments(&query, &accessor);

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
    fn generate_and_verify_proof_missing_data() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

        let accessor: OwnedTableTestAccessor<DoryEvaluationProof> = build_accessor(prover_setup);
        let query = build_missing_query(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();
        let query_commitments = proof_of_sql_verifier::compute_query_commitments(&query, &accessor);

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
    fn generate_and_verify_proof_missing_commitments() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

        let accessor: OwnedTableTestAccessor<DoryEvaluationProof> = build_accessor(prover_setup);
        let query = build_query(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        let query_commitments = QueryCommitments::new();

        let result = proof_of_sql_verifier::verify_dory_proof(
            proof,
            query.proof_expr(),
            &query_commitments,
            &query_data,
            &verifier_setup,
        );

        assert!(result.is_err());
    }

    #[test]
    fn generate_and_verify_proof_alternative_data() {
        let public_parameters = PublicParameters::rand(4, &mut test_rng());
        let ps = ProverSetup::from(&public_parameters);
        let vs = VerifierSetup::from(&public_parameters);
        let prover_setup = DoryProverPublicSetup::new(&ps, 4);
        let verifier_setup = DoryVerifierPublicSetup::new(&vs, 4);

        let accessor: OwnedTableTestAccessor<DoryEvaluationProof> = build_accessor(prover_setup);
        let query = build_query(&accessor);

        let proof = VerifiableQueryResult::<DoryEvaluationProof>::new(
            query.proof_expr(),
            &accessor,
            &prover_setup,
        );

        let query_data = proof
            .verify(query.proof_expr(), &accessor, &verifier_setup)
            .unwrap();

        let accessor: OwnedTableTestAccessor<DoryEvaluationProof> =
            build_alternative_accessor(prover_setup);
        let query_commitments = proof_of_sql_verifier::compute_query_commitments(&query, &accessor);

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
