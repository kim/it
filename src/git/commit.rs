// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use crate::ssh;

const SSHSIG_NAMESPACE: &str = "git";

pub fn commit_signed<'a, S>(
    signer: &mut S,
    repo: &'a git2::Repository,
    msg: impl AsRef<str>,
    tree: &git2::Tree<'a>,
    parents: &[&git2::Commit<'a>],
) -> crate::Result<git2::Oid>
where
    S: crate::keys::Signer + ?Sized,
{
    let aut = repo.signature()?;
    let buf = repo.commit_create_buffer(&aut, &aut, msg.as_ref(), tree, parents)?;
    let sig = {
        let hash = ssh::HashAlg::Sha512;
        let data = ssh::SshSig::signed_data(SSHSIG_NAMESPACE, hash, &buf)?;
        let sig = signer.sign(&data)?;
        ssh::SshSig::new(signer.ident().key_data(), SSHSIG_NAMESPACE, hash, sig)?
            .to_pem(ssh::LineEnding::LF)?
    };
    let oid = repo.commit_signed(
        buf.as_str().expect("commit buffer to be utf8"),
        sig.as_str(),
        None,
    )?;

    Ok(oid)
}

pub fn verify_commit_signature(
    repo: &git2::Repository,
    oid: &git2::Oid,
) -> crate::Result<ssh::PublicKey> {
    let (sig, data) = repo.extract_signature(oid, None)?;
    let sig = ssh::SshSig::from_pem(&*sig)?;
    let pk = ssh::PublicKey::from(sig.public_key().clone());
    pk.verify(SSHSIG_NAMESPACE, &data, &sig)?;

    Ok(pk)
}
