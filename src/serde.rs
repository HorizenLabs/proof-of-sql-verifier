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

pub type IndexMap = indexmap::IndexMap<
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

#[derive(Serialize, Deserialize)]
#[serde(remote = "OwnedTable<DoryScalar>")]
pub struct OwnedTableDef {
    #[serde(getter = "OwnedTable::inner_table", with = "index_map_serde")]
    table: IndexMap,
}

impl From<OwnedTableDef> for OwnedTable<DoryScalar> {
    fn from(value: OwnedTableDef) -> Self {
        Self::try_new(value.table).unwrap()
    }
}

mod index_map_serde {
    use super::*;
    use core::fmt;
    use serde::{
        de::{MapAccess, Visitor},
        ser::SerializeMap,
        Deserializer, Serializer,
    };
    use std::marker::PhantomData;

    #[derive(Serialize, Deserialize)]
    struct OwnedColumnWrap(#[serde(with = "OwnedColumnDef")] OwnedColumn<DoryScalar>);

    #[derive(Serialize, Deserialize)]
    #[serde(remote = "OwnedColumn<DoryScalar>")]
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

    pub fn serialize<S>(index_map: &IndexMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(index_map.len()))?;
        for (k, v) in index_map {
            map.serialize_entry(k, &OwnedColumnWrap(v.clone()))?;
        }
        map.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<IndexMap, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(IndexMapVisitor::new())
    }

    struct IndexMapVisitor {
        marker: PhantomData<fn() -> IndexMap>,
    }

    impl IndexMapVisitor {
        fn new() -> Self {
            IndexMapVisitor {
                marker: PhantomData,
            }
        }
    }

    impl<'de> Visitor<'de> for IndexMapVisitor {
        // The type that our Visitor is going to produce.
        type Value = IndexMap;

        // Format a message stating what data this Visitor expects to receive.
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a very special map")
        }

        // Deserialize MyMap from an abstract "map" provided by the
        // Deserializer. The MapAccess input is a callback provided by
        // the Deserializer to let us see each entry in the map.
        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut map =
                IndexMap::with_capacity_and_hasher(access.size_hint().unwrap_or(0), <_>::default());

            // While there are entries remaining in the input, add them
            // into our map.
            while let Some((key, OwnedColumnWrap(value))) = access.next_entry()? {
                map.insert(key, value);
            }

            Ok(map)
        }
    }
}
