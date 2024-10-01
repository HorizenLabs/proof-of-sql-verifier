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

use crate::serde::QueryDataDef;
use proof_of_sql::{
    base::{
        commitment::QueryCommitments,
        database::{ColumnType, OwnedColumn, OwnedTable},
        math::decimal::Precision,
    },
    proof_primitive::dory::{DoryCommitment, DoryScalar},
    sql::{proof::QueryData, proof_plans::DynProofPlan},
};
use proof_of_sql_parser::{
    posql_time::{PoSQLTimeUnit, PoSQLTimeZone},
    Identifier,
};
use serde::{Deserialize, Serialize};

use crate::VerifyError;

/// Represents the public input for a Dory proof.
///
/// This structure encapsulates the necessary public information required
/// for verifying a Dory proof, including the proof expression, commitments,
/// and query data.
#[derive(Serialize, Deserialize)]
pub struct DoryPublicInput {
    expr: DynProofPlan<DoryCommitment>,
    commitments: QueryCommitments<DoryCommitment>,
    #[serde(with = "QueryDataDef")]
    query_data: QueryData<DoryScalar>,
}

impl TryFrom<&[u8]> for DoryPublicInput {
    type Error = VerifyError;

    fn try_from(bytes: &[u8]) -> Result<Self, VerifyError> {
        DoryPublicInput::from_bytes(bytes).map_err(|_| VerifyError::InvalidInput)
    }
}

impl DoryPublicInput {
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
        let bytes = bincode::serialize(&expr).unwrap();
        let expr: DynProofPlan<DoryCommitment> = bincode::deserialize(&bytes).unwrap();
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
    pub fn into_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let mut expr_bytes = Vec::new();

        // Serialize the expression
        bincode::serialize_into(&mut expr_bytes, &self.expr).unwrap();

        // Serialize the commitments
        bincode::serialize_into(&mut expr_bytes, &self.commitments).unwrap();

        // Serialize the table data
        let table = self.query_data.table.inner_table();

        // usize is serialized as u32, as usize is platform dependent
        bincode::serialize_into(&mut expr_bytes, &(table.len() as u32)).unwrap();

        for (k, v) in table {
            bincode::serialize_into(&mut expr_bytes, k).unwrap();
            bincode::serialize_into(&mut expr_bytes, &v.column_type()).unwrap();

            match v {
                OwnedColumn::Boolean(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::SmallInt(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::Int(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::BigInt(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::VarChar(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::Int128(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::Decimal75(precision, scale, v) => {
                    bincode::serialize_into(&mut expr_bytes, precision).unwrap();
                    bincode::serialize_into(&mut expr_bytes, scale).unwrap();
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::Scalar(v) => {
                    bincode::serialize_into(&mut expr_bytes, v).unwrap();
                }
                OwnedColumn::TimestampTZ(unit, zone, vv) => {
                    bincode::serialize_into(&mut expr_bytes, unit).unwrap();
                    bincode::serialize_into(&mut expr_bytes, zone).unwrap();
                    bincode::serialize_into(&mut expr_bytes, vv).unwrap();
                }
                &_ => {
                    return Err(VerifyError::InvalidInput);
                }
            }
        }

        bincode::serialize_into(&mut expr_bytes, &self.query_data.verification_hash).unwrap();

        Ok(expr_bytes)
    }

    /// Converts a byte array into a `DoryPublicInput` instance.
    fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        let mut cursor = std::io::Cursor::new(bytes);

        // Deserialize the expression
        let expr: DynProofPlan<DoryCommitment> = bincode::deserialize_from(&mut cursor)?;

        // Deserialize the commitments
        let commitments: QueryCommitments<DoryCommitment> = bincode::deserialize_from(&mut cursor)?;

        let table_len: u32 = bincode::deserialize_from(&mut cursor)?;

        // Deserialize the table data
        let mut vector = Vec::<(Identifier, OwnedColumn<_>)>::new();
        while cursor.position() < bytes.len() as u64 && vector.len() < table_len as usize {
            let k: String = bincode::deserialize_from(&mut cursor)?;
            let column_type: ColumnType = bincode::deserialize_from(&mut cursor)?;
            let identifier =
                Identifier::try_new(k).map_err(|e| bincode::ErrorKind::Custom(e.to_string()))?;

            let column: OwnedColumn<DoryScalar> = match column_type {
                ColumnType::Boolean => {
                    let v: Vec<bool> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::Boolean(v)
                }
                ColumnType::SmallInt => {
                    let v: Vec<i16> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::SmallInt(v)
                }
                ColumnType::Int => {
                    let v: Vec<i32> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::Int(v)
                }
                ColumnType::BigInt => {
                    let v: Vec<i64> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::BigInt(v)
                }
                ColumnType::VarChar => {
                    let v: Vec<String> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::VarChar(v)
                }
                ColumnType::Int128 => {
                    let v: Vec<i128> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::Int128(v)
                }
                ColumnType::Decimal75(_, _) => {
                    let precision: Precision = bincode::deserialize_from(&mut cursor)?;
                    let scale: i8 = bincode::deserialize_from(&mut cursor)?;
                    let v: Vec<DoryScalar> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::Decimal75(precision, scale, v)
                }
                ColumnType::Scalar => {
                    let v: Vec<DoryScalar> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::Scalar(v)
                }
                ColumnType::TimestampTZ(_, _) => {
                    let unit: PoSQLTimeUnit = bincode::deserialize_from(&mut cursor)?;
                    let zone: PoSQLTimeZone = bincode::deserialize_from(&mut cursor)?;
                    let vv: Vec<i64> = bincode::deserialize_from(&mut cursor)?;
                    OwnedColumn::TimestampTZ(unit, zone, vv)
                }
            };

            vector.push((identifier, column));
        }
        let table = OwnedTable::try_from_iter(vector)
            .map_err(|e| bincode::ErrorKind::Custom(e.to_string()))?;

        let verification_hash: [u8; 32] = bincode::deserialize_from(&mut cursor)?;
        let query_data = QueryData {
            table,
            verification_hash,
        };

        Ok(DoryPublicInput {
            expr,
            commitments,
            query_data,
        })
    }
}

#[cfg(test)]
mod test {

    use proof_of_sql::{
        base::{
            commitment::{Commitment, CommitmentEvaluationProof, QueryCommitmentsExt},
            database::{
                owned_table_utility::*, CommitmentAccessor, OwnedTableTestAccessor, SchemaAccessor,
                TestAccessor,
            },
        },
        proof_primitive::dory::{
            test_rng, DoryEvaluationProof, DoryProverPublicSetup, ProverSetup, PublicParameters,
        },
        sql::{
            parse::QueryExpr,
            proof::{ProofPlan, VerifiableQueryResult},
        },
    };

    use crate::{DoryProof, VerificationKey};

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
    fn test_dory_public_input() {
        // Initialize setup
        let public_parameters = PublicParameters::rand(6, &mut test_rng());
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
            .verify(query.proof_expr(), &accessor, &vk.into_dory())
            .unwrap();
        let query_commitments = compute_query_commitments(&query, &accessor);

        // Verify proof
        let pubs = DoryPublicInput::new(query.proof_expr(), query_commitments, query_data);

        let bytes = pubs.into_bytes().unwrap();

        let pubs = DoryPublicInput::try_from(&bytes[..]).unwrap();
        let proof = DoryProof::new(proof);
        let result = crate::verify_dory_proof(&proof, &pubs, &vk);

        assert!(result.is_ok());
    }
}
