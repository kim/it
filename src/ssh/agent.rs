// Copyright © 2022 Kim Altintop <kim@eagain.io>
// SPDX-License-Identifier: GPL-2.0-only WITH openvpn-openssl-exception

use std::{
    env,
    io::{
        self,
        ErrorKind::*,
    },
};

use anyhow::Context;
use ssh_encoding::{
    CheckedSum,
    Decode,
    Encode,
    Reader,
    Writer,
};
use ssh_key::{
    public::KeyData,
    Algorithm,
    HashAlg,
    PublicKey,
    Signature,
};

#[cfg(unix)]
pub use std::os::unix::net::UnixStream;
#[cfg(windows)]
pub use uds_windows::UnixStram;

const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";

const MAX_AGENT_REPLY_LEN: usize = 256 * 1024;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

pub struct Client<T> {
    conn: T,
}

impl Client<UnixStream> {
    pub fn from_env() -> io::Result<Self> {
        let path = env::var_os(SSH_AUTH_SOCK).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "SSH_AUTH_SOCK environment variable not set",
            )
        })?;
        UnixStream::connect(path).map(Self::from)
    }
}

impl From<UnixStream> for Client<UnixStream> {
    fn from(conn: UnixStream) -> Self {
        Self { conn }
    }
}

impl<'a> From<&'a UnixStream> for Client<&'a UnixStream> {
    fn from(conn: &'a UnixStream) -> Self {
        Self { conn }
    }
}

impl<T> Client<T>
where
    T: io::Read + io::Write,
{
    pub fn sign(&mut self, key: &PublicKey, msg: impl AsRef<[u8]>) -> io::Result<Signature> {
        request(
            &mut self.conn,
            SignRequest {
                key,
                msg: msg.as_ref(),
            },
        )
        .map(|SignResponse { sig }| sig)
    }

    pub fn list_keys(&mut self) -> io::Result<Vec<PublicKey>> {
        request(&mut self.conn, RequestIdentities).map(|IdentitiesAnswer { keys }| keys)
    }
}

trait Request: Encode<Error = crate::Error> {
    type Response: Response;
}

trait Response: Decode<Error = crate::Error> {
    const SUCCESS: u8;
}

fn request<I, T>(mut io: I, req: T) -> io::Result<T::Response>
where
    I: io::Read + io::Write,
    T: Request,
{
    send(&mut io, req)?;
    let resp = recv(&mut io)?;
    let mut reader = resp.as_slice();
    match u8::decode(&mut reader).map_err(|_| unknown_response())? {
        x if x == T::Response::SUCCESS => T::Response::decode(&mut reader).map_err(decode),
        SSH_AGENT_FAILURE => Err(agent_error()),
        _ => Err(unknown_response()),
    }
}

fn send<W, T>(mut io: W, req: T) -> io::Result<()>
where
    W: io::Write,
    T: Encode<Error = crate::Error>,
{
    let len = req.encoded_len_prefixed().map_err(encode)?;
    let mut buf = Vec::with_capacity(len);
    req.encode_prefixed(&mut buf).map_err(encode)?;

    io.write_all(&buf)?;
    io.flush()?;

    Ok(())
}

fn recv<R: io::Read>(mut io: R) -> io::Result<Vec<u8>> {
    let want = {
        let mut buf = [0; 4];
        io.read_exact(&mut buf)?;
        u32::from_be_bytes(buf) as usize
    };

    if want < 1 {
        return Err(incomplete_response());
    }
    if want > MAX_AGENT_REPLY_LEN {
        return Err(reponse_too_large());
    }

    let mut buf = vec![0; want];
    io.read_exact(&mut buf)?;

    Ok(buf)
}

struct SignRequest<'a> {
    key: &'a PublicKey,
    msg: &'a [u8],
}

impl Request for SignRequest<'_> {
    type Response = SignResponse;
}

impl Encode for SignRequest<'_> {
    type Error = crate::Error;

    fn encoded_len(&self) -> Result<usize, Self::Error> {
        Ok([
            self.key.key_data().encoded_len_prefixed()?,
            self.msg.encoded_len()?,
            SSH_AGENTC_SIGN_REQUEST.encoded_len()?,
            4, // flags
        ]
        .checked_sum()?)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Self::Error> {
        SSH_AGENTC_SIGN_REQUEST.encode(writer)?;
        self.key.key_data().encode_prefixed(writer)?;
        self.msg.encode(writer)?;
        let flags = match self.key.algorithm() {
            Algorithm::Rsa { hash } => match hash {
                Some(HashAlg::Sha256) => SSH_AGENT_RSA_SHA2_256,
                _ => SSH_AGENT_RSA_SHA2_512, // sane default
            },
            _ => 0,
        };
        flags.encode(writer)?;
        Ok(())
    }
}

struct SignResponse {
    sig: Signature,
}

impl Response for SignResponse {
    const SUCCESS: u8 = SSH_AGENT_SIGN_RESPONSE;
}

impl Decode for SignResponse {
    type Error = crate::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let sig = reader.read_prefixed(Signature::decode)?;
        Ok(Self { sig })
    }
}

struct RequestIdentities;

impl Request for RequestIdentities {
    type Response = IdentitiesAnswer;
}

impl Encode for RequestIdentities {
    type Error = crate::Error;

    fn encoded_len(&self) -> Result<usize, Self::Error> {
        Ok(SSH_AGENTC_REQUEST_IDENTITIES.encoded_len()?)
    }

    fn encode(&self, writer: &mut impl Writer) -> Result<(), Self::Error> {
        Ok(SSH_AGENTC_REQUEST_IDENTITIES.encode(writer)?)
    }
}

struct IdentitiesAnswer {
    keys: Vec<PublicKey>,
}

impl Response for IdentitiesAnswer {
    const SUCCESS: u8 = SSH_AGENT_IDENTITIES_ANSWER;
}

impl Decode for IdentitiesAnswer {
    type Error = crate::Error;

    fn decode(reader: &mut impl Reader) -> Result<Self, Self::Error> {
        let nkeys = usize::decode(reader).context("nkeys")?;
        let mut keys = Vec::with_capacity(nkeys);

        for _ in 0..nkeys {
            let key_data = reader.read_prefixed(KeyData::decode).context("key data")?;
            let comment = String::decode(reader).context("comment")?;
            keys.push(PublicKey::new(key_data, comment));
        }

        Ok(Self { keys })
    }
}

fn e(kind: io::ErrorKind, msg: &str) -> io::Error {
    io::Error::new(kind, msg)
}

fn ee(kind: io::ErrorKind, e: crate::Error) -> io::Error {
    io::Error::new(kind, e)
}

fn incomplete_response() -> io::Error {
    e(UnexpectedEof, "incomplete response")
}

fn reponse_too_large() -> io::Error {
    e(Unsupported, "response payload too large")
}

fn encode(e: crate::Error) -> io::Error {
    ee(InvalidData, e.context("failed to encode request"))
}

fn decode(e: crate::Error) -> io::Error {
    ee(InvalidData, e.context("failed to decode response"))
}

fn agent_error() -> io::Error {
    e(Other, "error response from agent")
}

fn unknown_response() -> io::Error {
    e(Unsupported, "unknown response")
}
