// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

pub mod paths {
    use directories::ProjectDirs;
    use std::path::{
        Path,
        PathBuf,
    };

    pub fn ids() -> PathBuf {
        project_dirs().data_dir().join("ids")
    }

    /// Default path where to store bundles.
    ///
    /// This is a relative path, to be treated as relative to GIT_DIR.
    pub fn bundles() -> &'static Path {
        Path::new("it/bundles")
    }

    fn project_dirs() -> ProjectDirs {
        ProjectDirs::from("io", "eagain", "it").expect("no valid $HOME")
    }
}

pub mod git {
    use std::path::Path;

    use anyhow::{
        anyhow,
        bail,
        ensure,
    };
    use zeroize::Zeroizing;

    use crate::{
        git::{
            self,
            if_not_found_none,
            Refname,
        },
        keys::{
            Agent,
            Signer,
        },
        metadata::IdentityId,
        ssh::{
            self,
            agent,
        },
    };

    /// Last resort to override the signing key, if neither [`USER_SIGNING_KEY`]
    /// nor [`SSH_KEY_COMMAND`] will cut it.
    pub const IT_SIGNING_KEY: &str = "it.signingKey";
    /// The default `it` identity to use.
    pub const IT_ID: &str = "it.id";
    /// Command to dynamically set the signing key, see
    /// [`gpg.ssh.defaultKeyCommand`]
    ///
    /// [`gpg.ssh.defaultKeyCommand`]: https://git-scm.com/docs/git-config#Documentation/git-config.txt-gpgsshdefaultKeyCommand
    pub const SSH_KEY_COMMAND: &str = "gpg.ssh.defaultKeyCommand";
    /// The key to sign git and it objects with, see [`user.signingKey`]
    ///
    /// [`user.signingKey`]: https://git-scm.com/docs/git-config#Documentation/git-config.txt-usersigningKey
    pub const USER_SIGNING_KEY: &str = "user.signingKey";
    /// The default branch name, see [`init.defaultBranch`]
    ///
    /// If not set, the default branch is "master".
    ///
    /// [`init.defaultBranch`]: https://git-scm.com/docs/git-config#Documentation/git-config.txt-initdefaultBranch
    pub const DEFAULT_BRANCH: &str = "init.defaultBranch";

    #[allow(clippy::large_enum_variant)]
    pub enum Key {
        Secret(ssh::PrivateKey),
        Public(ssh::PublicKey),
    }

    impl Key {
        pub fn public(&self) -> &ssh::PublicKey {
            match self {
                Self::Secret(sk) => sk.public_key(),
                Self::Public(pk) => pk,
            }
        }
    }

    pub fn signing_key(c: &git2::Config) -> crate::Result<Option<Key>> {
        match if_not_found_none(c.get_string(IT_SIGNING_KEY))? {
            Some(v) => ssh_signing_key_from_config_value(v).map(Some),
            None => ssh_signing_key(c)
                .transpose()
                .or_else(|| ssh_key_command(c).transpose())
                .transpose(),
        }
    }

    pub fn signer<F>(c: &git2::Config, askpass: F) -> crate::Result<Box<dyn Signer>>
    where
        F: Fn(&str) -> crate::Result<Zeroizing<Vec<u8>>>,
    {
        let key = signing_key(c)?.ok_or_else(|| anyhow!("no signing key in git config"))?;
        match key {
            Key::Public(pk) => {
                let client = agent::Client::from_env()?;
                Ok(Box::new(Agent::new(client, pk.into())))
            },
            Key::Secret(sk) => {
                if sk.is_encrypted() {
                    let prompt = format!(
                        "`it` wants to use the key {}. Please provide a passphrase to decrypt it",
                        sk.public_key().to_openssh()?
                    );
                    for _ in 0..3 {
                        let pass = askpass(&prompt)?;
                        if let Ok(key) = sk.decrypt(pass) {
                            return Ok(Box::new(key));
                        }
                    }
                    bail!("unable to decrypt secret key");
                } else {
                    Ok(Box::new(sk))
                }
            },
        }
    }

    pub fn identity(c: &git2::Config) -> crate::Result<Option<IdentityId>> {
        if_not_found_none(c.get_string(IT_ID))?
            .map(IdentityId::try_from)
            .transpose()
            .map_err(Into::into)
    }

    pub fn ssh_signing_key(cfg: &git2::Config) -> crate::Result<Option<Key>> {
        if_not_found_none(cfg.get_string(USER_SIGNING_KEY))?
            .map(ssh_signing_key_from_config_value)
            .transpose()
    }

    pub(crate) fn ssh_signing_key_from_config_value<V: AsRef<str>>(v: V) -> crate::Result<Key> {
        match v.as_ref().strip_prefix("key::") {
            Some(lit) => {
                let key = ssh::PublicKey::from_openssh(lit)?;
                Ok(Key::Public(key))
            },
            None => {
                let path = Path::new(v.as_ref());
                ensure!(
                    path.exists(),
                    "{} is not a valid path to an SSH private key",
                    path.display()
                );
                let key = ssh::PrivateKey::read_openssh_file(path)?;
                Ok(Key::Secret(key))
            },
        }
    }

    pub fn ssh_key_command(cfg: &git2::Config) -> crate::Result<Option<Key>> {
        let out = git::config_command(cfg, SSH_KEY_COMMAND)?;
        let key = out
            .as_deref()
            .map(ssh::PublicKey::from_openssh)
            .transpose()?
            .map(Key::Public);

        Ok(key)
    }

    pub fn default_branch(cfg: &git2::Config) -> crate::Result<Refname> {
        if_not_found_none(cfg.get_string(DEFAULT_BRANCH))?
            .unwrap_or_else(|| String::from("master"))
            .try_into()
            .map_err(Into::into)
    }
}
pub use git::signer;
