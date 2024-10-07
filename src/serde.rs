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
use serde::{Deserialize, Serialize};

pub type IndexMap =
    indexmap::IndexMap<Identifier, OwnedColumnDef, core::hash::BuildHasherDefault<ahash::AHasher>>;

#[derive(Serialize, Deserialize, Clone)]
pub struct QueryDataDef {
    table: OwnedTableDef,
    verification_hash: [u8; 32],
}

impl From<QueryDataDef> for QueryData<DoryScalar> {
    fn from(value: QueryDataDef) -> Self {
        QueryData {
            table: OwnedTable::from(value.table),
            verification_hash: value.verification_hash,
        }
    }
}

impl From<QueryData<DoryScalar>> for QueryDataDef {
    fn from(value: QueryData<DoryScalar>) -> Self {
        Self {
            table: value.table.into(),
            verification_hash: value.verification_hash,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct OwnedTableDef {
    table: IndexMap,
}

impl From<OwnedTable<DoryScalar>> for OwnedTableDef {
    fn from(value: OwnedTable<DoryScalar>) -> Self {
        Self {
            table: value
                .inner_table()
                .iter()
                .map(|(k, v)| (*k, OwnedColumnDef::from(v.clone())))
                .collect(),
        }
    }
}

impl From<OwnedTableDef> for OwnedTable<DoryScalar> {
    fn from(value: OwnedTableDef) -> Self {
        Self::try_new(
            value
                .table
                .iter()
                .map(|(k, v)| (*k, OwnedColumn::<DoryScalar>::from(v.clone())))
                .collect(),
        )
        .unwrap()
    }
}

#[derive(Serialize, Deserialize)]
struct OwnedColumnWrap(OwnedColumnDef);

#[derive(Serialize, Deserialize, Clone)]
#[non_exhaustive]
pub enum OwnedColumnDef {
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

impl From<OwnedColumnDef> for OwnedColumn<DoryScalar> {
    fn from(value: OwnedColumnDef) -> Self {
        match value {
            OwnedColumnDef::Boolean(v) => OwnedColumn::Boolean(v),
            OwnedColumnDef::SmallInt(v) => OwnedColumn::SmallInt(v),
            OwnedColumnDef::Int(v) => OwnedColumn::Int(v),
            OwnedColumnDef::BigInt(v) => OwnedColumn::BigInt(v),
            OwnedColumnDef::VarChar(v) => OwnedColumn::VarChar(v),
            OwnedColumnDef::Int128(v) => OwnedColumn::Int128(v),
            OwnedColumnDef::Decimal75(precision, scale, v) => {
                OwnedColumn::Decimal75(precision, scale, v)
            }
            OwnedColumnDef::Scalar(v) => OwnedColumn::Scalar(v),
            OwnedColumnDef::TimestampTZ(unit, tz, v) => OwnedColumn::TimestampTZ(unit, tz, v),
        }
    }
}

impl From<OwnedColumn<DoryScalar>> for OwnedColumnDef {
    fn from(value: OwnedColumn<DoryScalar>) -> Self {
        match value {
            OwnedColumn::Boolean(v) => OwnedColumnDef::Boolean(v),
            OwnedColumn::SmallInt(v) => OwnedColumnDef::SmallInt(v),
            OwnedColumn::Int(v) => OwnedColumnDef::Int(v),
            OwnedColumn::BigInt(v) => OwnedColumnDef::BigInt(v),
            OwnedColumn::VarChar(v) => OwnedColumnDef::VarChar(v),
            OwnedColumn::Int128(v) => OwnedColumnDef::Int128(v),
            OwnedColumn::Decimal75(precision, scale, v) => {
                OwnedColumnDef::Decimal75(precision, scale, v)
            }
            OwnedColumn::Scalar(v) => OwnedColumnDef::Scalar(v),
            OwnedColumn::TimestampTZ(unit, tz, v) => OwnedColumnDef::TimestampTZ(unit, tz, v),
            _ => unimplemented!("Missing field"),
        }
    }
}
