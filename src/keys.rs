// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use core::fmt;
use std::{
    borrow::Cow,
    io,
    ops::{
        Deref,
        DerefMut,
    },
    str::FromStr,
};

use anyhow::anyhow;
use signature::SignerMut;

use crate::{
    cfg,
    metadata,
    ssh::{
        self,
        agent,
    },
};

pub type Signature = ssh::Signature;

pub trait Signer {
    fn ident(&self) -> VerificationKey;
    fn sign(&mut self, msg: &[u8]) -> Result<ssh::Signature, signature::Error>;
}

impl<T> Signer for Box<T>
where
    T: Signer + ?Sized,
{
    fn ident(&self) -> VerificationKey {
        self.deref().ident()
    }

    fn sign(&mut self, msg: &[u8]) -> Result<ssh::Signature, signature::Error> {
        self.deref_mut().sign(msg)
    }
}

impl Signer for ssh::PrivateKey {
    fn ident(&self) -> VerificationKey {
        self.public_key().into()
    }

    fn sign(&mut self, msg: &[u8]) -> Result<ssh::Signature, signature::Error> {
        self.try_sign(msg)
    }
}

pub struct Agent<T> {
    client: agent::Client<T>,
    ident: ssh::PublicKey,
}

impl Agent<agent::UnixStream> {
    pub fn from_gitconfig(cfg: &git2::Config) -> crate::Result<Self> {
        let client = agent::Client::from_env()?;
        let ident = VerificationKey::from_gitconfig(cfg)?.0.into_owned();

        Ok(Self { client, ident })
    }

    pub fn boxed(self) -> Box<dyn Signer> {
        Box::new(self)
    }

    pub fn as_dyn(&mut self) -> &mut dyn Signer {
        self
    }
}

impl<T> Agent<T> {
    pub fn new(client: agent::Client<T>, key: VerificationKey<'_>) -> Self {
        let ident = key.0.into_owned();
        Self { client, ident }
    }

    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey::from(&self.ident)
    }
}

impl<T> Signer for Agent<T>
where
    T: io::Read + io::Write,
{
    fn ident(&self) -> VerificationKey {
        self.verification_key()
    }

    fn sign(&mut self, msg: &[u8]) -> Result<ssh::Signature, signature::Error> {
        self.client
            .sign(&self.ident, msg)
            .map_err(signature::Error::from_source)
    }
}

impl<T> Signer for &mut Agent<T>
where
    T: io::Read + io::Write,
{
    fn ident(&self) -> VerificationKey {
        self.verification_key()
    }

    fn sign(&mut self, msg: &[u8]) -> Result<ssh::Signature, signature::Error> {
        self.client
            .sign(&self.ident, msg)
            .map_err(signature::Error::from_source)
    }
}

#[derive(Clone)]
pub struct VerificationKey<'a>(Cow<'a, ssh::PublicKey>);

impl<'a> VerificationKey<'a> {
    pub fn from_openssh(key: &str) -> Result<Self, ssh::Error> {
        ssh::PublicKey::from_openssh(key).map(Cow::Owned).map(Self)
    }

    pub fn to_openssh(&self) -> Result<String, ssh::Error> {
        self.0.to_openssh()
    }

    pub fn from_gitconfig(cfg: &git2::Config) -> crate::Result<Self> {
        let key = cfg::git::signing_key(cfg)?
            .ok_or_else(|| anyhow!("unable to determine signing key from git config"))?
            .public()
            .to_owned();
        Ok(Self(Cow::Owned(key)))
    }

    pub fn algorithm(&self) -> ssh::Algorithm {
        self.0.algorithm()
    }

    pub fn strip_comment(&mut self) {
        self.0.to_mut().set_comment("")
    }

    pub fn without_comment(mut self) -> Self {
        self.strip_comment();
        self
    }

    pub fn sha256(&self) -> [u8; 32] {
        self.0.fingerprint(ssh::HashAlg::Sha256).sha256().unwrap()
    }

    pub fn to_owned<'b>(&self) -> VerificationKey<'b> {
        VerificationKey(Cow::Owned(self.0.clone().into_owned()))
    }

    pub fn keyid(&self) -> metadata::KeyId {
        metadata::KeyId::from(self)
    }

    pub(crate) fn key_data(&self) -> ssh::public::KeyData {
        self.as_ref().into()
    }
}

impl AsRef<ssh::PublicKey> for VerificationKey<'_> {
    fn as_ref(&self) -> &ssh::PublicKey {
        &self.0
    }
}

impl fmt::Display for VerificationKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0.to_string())
    }
}

impl From<ssh::PublicKey> for VerificationKey<'_> {
    fn from(key: ssh::PublicKey) -> Self {
        Self(Cow::Owned(key))
    }
}

impl<'a> From<&'a ssh::PublicKey> for VerificationKey<'a> {
    fn from(key: &'a ssh::PublicKey) -> Self {
        Self(Cow::Borrowed(key))
    }
}

impl FromStr for VerificationKey<'_> {
    type Err = ssh::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_openssh(s)
    }
}

impl signature::Verifier<ssh::Signature> for VerificationKey<'_> {
    fn verify(&self, msg: &[u8], signature: &ssh::Signature) -> Result<(), signature::Error> {
        signature::Verifier::verify(&*self.0, msg, signature)
    }
}
