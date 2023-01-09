// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::str::FromStr;

use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    Serializer,
};

pub mod oid {
    use super::*;

    #[derive(serde::Serialize, serde::Deserialize)]
    pub struct Oid(#[serde(with = "self")] pub git2::Oid);

    impl From<git2::Oid> for Oid {
        fn from(oid: git2::Oid) -> Self {
            Self(oid)
        }
    }

    pub fn serialize<S>(oid: &git2::Oid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&oid.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<git2::Oid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex: &str = Deserialize::deserialize(deserializer)?;
        git2::Oid::from_str(hex).map_err(serde::de::Error::custom)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S>(oid: &Option<git2::Oid>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            oid.as_ref().map(ToString::to_string).serialize(serializer)
        }

        #[allow(unused)]
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<git2::Oid>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let hex: Option<&str> = Deserialize::deserialize(deserializer)?;
            hex.map(FromStr::from_str)
                .transpose()
                .map_err(serde::de::Error::custom)
        }
    }
}
