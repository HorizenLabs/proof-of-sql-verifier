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

use crate::errors::VerifyError;
use alloc::{string::String, vec::Vec};
use proof_of_sql::{
    base::{
        database::{OwnedColumn, OwnedTable},
        math::decimal::Precision,
    },
    proof_primitive::dory::DoryScalar,
    sql::proof::QueryData,
};
use proof_of_sql_parser::{
    posql_time::{PoSQLTimeUnit, PoSQLTimeZone},
    Identifier,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::{serde_as, DeserializeAs, MapPreventDuplicates, SerializeAs};

type IndexMap = indexmap::IndexMap<
    Identifier,
    OwnedColumn<DoryScalar>,
    core::hash::BuildHasherDefault<ahash::AHasher>,
>;

#[derive(Serialize, Deserialize)]
#[serde(remote = "QueryData<DoryScalar>")]
pub(crate) struct QueryDataDef {
    #[serde(with = "OwnedTableDef")]
    table: OwnedTable<DoryScalar>,
    verification_hash: [u8; 32],
}

#[serde_as]
#[derive(Serialize, Deserialize)]
struct RaggedTable {
    #[serde_as(as = "MapPreventDuplicates<_, OwnedColumnDef>")]
    table: IndexMap,
}

#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "OwnedTable<DoryScalar>", try_from = "RaggedTable")]
struct OwnedTableDef {
    #[serde_as(as = "MapPreventDuplicates<_, OwnedColumnDef>")]
    #[serde(getter = "OwnedTable::inner_table")]
    table: IndexMap,
}

impl TryFrom<RaggedTable> for OwnedTable<DoryScalar> {
    type Error = VerifyError;

    fn try_from(value: RaggedTable) -> Result<Self, Self::Error> {
        Self::try_new(value.table).map_err(|_| VerifyError::InvalidInput)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "OwnedColumn<DoryScalar>")]
#[non_exhaustive]
enum OwnedColumnDef {
    Boolean(Vec<bool>),
    SmallInt(Vec<i16>),
    Int(Vec<i32>),
    BigInt(Vec<i64>),
    VarChar(Vec<String>),
    Int128(Vec<i128>),
    Decimal75(Precision, i8, Vec<DoryScalar>),
    Scalar(Vec<DoryScalar>),
    TimestampTZ(PoSQLTimeUnit, PoSQLTimeZone, Vec<i64>),
}

impl SerializeAs<OwnedColumn<DoryScalar>> for OwnedColumnDef {
    fn serialize_as<S>(source: &OwnedColumn<DoryScalar>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        OwnedColumnDef::serialize(source, serializer)
    }
}

impl<'de> DeserializeAs<'de, OwnedColumn<DoryScalar>> for OwnedColumnDef {
    fn deserialize_as<D>(deserializer: D) -> Result<OwnedColumn<DoryScalar>, D::Error>
    where
        D: Deserializer<'de>,
    {
        OwnedColumnDef::deserialize(deserializer)
    }
}

#[cfg(test)]
mod owned_table {
    use super::*;

    use core::str::FromStr;

    use indexmap::IndexMap;
    use proof_of_sql::base::scalar::Scalar;

    #[derive(Serialize, Deserialize)]
    #[serde(transparent)]
    struct Wrapper(#[serde(with = "OwnedTableDef")] OwnedTable<DoryScalar>);

    #[test]
    fn deserialization_should_fail_with_different_column_lengths() {
        let invalid_table_toml = r#"
            {
                "table": {
                    "first_column": {
                    "Boolean": [
                        true,
                        false
                    ]
                    },
                    "second_column": {
                    "Boolean": [
                        false
                    ]
                    }
                }
            }
        "#;
        assert!(serde_json::from_str::<Wrapper>(&invalid_table_toml).is_err())
    }

    #[test]
    fn serialization_should_preserve_order() {
        let mut table = IndexMap::default();
        table.insert(
            Identifier::from_str("b").unwrap(),
            OwnedColumn::try_from_scalars(
                &[DoryScalar::ONE, DoryScalar::ZERO],
                proof_of_sql::base::database::ColumnType::Boolean,
            )
            .unwrap(),
        );
        table.insert(
            Identifier::from_str("a").unwrap(),
            OwnedColumn::try_from_scalars(
                &[DoryScalar::ZERO, DoryScalar::ONE],
                proof_of_sql::base::database::ColumnType::Boolean,
            )
            .unwrap(),
        );
        let owned_table = OwnedTable::try_new(table).unwrap();

        let mut buffer = Vec::new();
        ciborium::into_writer(&Wrapper(owned_table.clone()), &mut buffer).unwrap();
        let Wrapper(deserialized_owned_table) = ciborium::from_reader(&buffer[..]).unwrap();

        assert_eq!(
            owned_table.inner_table().len(),
            deserialized_owned_table.inner_table().len()
        );
        assert!(owned_table
            .inner_table()
            .iter()
            .zip(deserialized_owned_table.inner_table().iter())
            .all(|((k_0, _), (k_1, _))| k_0 == k_1))
    }
}
