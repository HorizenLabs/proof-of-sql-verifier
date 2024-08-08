use crate::QueryCommitments;
use proof_of_sql::{
    base::{
        commitment::{Commitment, QueryCommitmentsExt},
        database::{CommitmentAccessor, SchemaAccessor},
    },
    sql::{parse::QueryExpr, proof::ProofExpr},
};

pub fn compute_query_commitments<C: Commitment>(
    query_expr: &QueryExpr<C>,
    accessor: &(impl CommitmentAccessor<C> + SchemaAccessor),
) -> QueryCommitments<C> {
    let columns = query_expr.proof_expr().get_column_references();
    QueryCommitments::from_accessor_with_max_bounds(columns, accessor)
}
