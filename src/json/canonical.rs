// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    collections::BTreeMap,
    io::Write,
};

use unicode_normalization::{
    is_nfc_quick,
    IsNormalized,
    UnicodeNormalization as _,
};

use crate::metadata;

pub mod error {
    use std::io;

    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum Canonicalise {
        #[error(transparent)]
        Cjson(#[from] Float),

        #[error(transparent)]
        Json(#[from] serde_json::Error),

        #[error(transparent)]
        Io(#[from] io::Error),
    }

    #[derive(Debug, Error)]
    #[error("cannot canonicalise floating-point number")]
    pub struct Float;
}

pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl TryFrom<&serde_json::Value> for Value {
    type Error = error::Float;

    fn try_from(js: &serde_json::Value) -> Result<Self, Self::Error> {
        match js {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(b) => Ok(Self::Bool(*b)),
            serde_json::Value::Number(n) => n
                .as_i64()
                .map(Number::I64)
                .or_else(|| n.as_u64().map(Number::U64))
                .map(Self::Number)
                .ok_or(error::Float),
            serde_json::Value::String(s) => Ok(Self::String(to_nfc(s))),
            serde_json::Value::Array(v) => {
                let mut out = Vec::with_capacity(v.len());
                for w in v.iter().map(TryFrom::try_from) {
                    out.push(w?);
                }
                Ok(Self::Array(out))
            },
            serde_json::Value::Object(m) => {
                let mut out = BTreeMap::new();
                for (k, v) in m {
                    out.insert(to_nfc(k), Self::try_from(v)?);
                }
                Ok(Self::Object(out))
            },
        }
    }
}

impl TryFrom<&metadata::Custom> for Value {
    type Error = error::Float;

    fn try_from(js: &metadata::Custom) -> Result<Self, Self::Error> {
        let mut out = BTreeMap::new();
        for (k, v) in js {
            out.insert(to_nfc(k), Self::try_from(v)?);
        }
        Ok(Self::Object(out))
    }
}

impl serde::Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Number(n) => n.serialize(serializer),
            Value::String(s) => serializer.serialize_str(s),
            Value::Array(v) => v.serialize(serializer),
            Value::Object(m) => {
                use serde::ser::SerializeMap;

                let mut map = serializer.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            },
        }
    }
}

pub(crate) enum Number {
    I64(i64),
    U64(u64),
}

impl serde::Serialize for Number {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Number::I64(n) => serializer.serialize_i64(*n),
            Number::U64(n) => serializer.serialize_u64(*n),
        }
    }
}

fn to_nfc(s: &String) -> String {
    match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => s.clone(),
        IsNormalized::No | IsNormalized::Maybe => s.nfc().collect(),
    }
}

pub fn to_writer<W, T>(out: W, v: T) -> Result<(), error::Canonicalise>
where
    W: Write,
    T: serde::Serialize,
{
    let js = serde_json::to_value(v)?;
    let cj = Value::try_from(&js)?;
    serde_json::to_writer(out, &cj).map_err(|e| {
        if e.is_io() {
            error::Canonicalise::Io(e.into())
        } else {
            error::Canonicalise::Json(e)
        }
    })?;

    Ok(())
}

pub fn to_vec<T>(v: T) -> Result<Vec<u8>, error::Canonicalise>
where
    T: serde::Serialize,
{
    let mut buf = Vec::new();
    to_writer(&mut buf, v)?;

    Ok(buf)
}
