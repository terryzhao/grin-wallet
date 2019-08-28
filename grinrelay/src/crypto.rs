// Copyright 2018 The Vault713 Developers
// Modifications Copyright 2019 The Gotts Developers
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

//! Grin Relay Crypto APIs

use rustc_serialize::hex::{FromHex, ToHex};
use sha2::{Digest, Sha256};

use crate::bech32::Bech32;
use crate::error::ErrorKind;
use crate::Result;
use crate::{Commitment, Message, PublicKey, Secp256k1, SecretKey, Signature};

/// Encode the provided bytes into a hex string
pub fn to_hex(bytes: Vec<u8>) -> String {
	bytes.to_hex()
}

/// Decode a hex string into bytes (no '0x' prefix).
pub fn from_hex(hex_str: String) -> Result<Vec<u8>> {
	hex_str
		.from_hex()
		.map_err(|_| ErrorKind::NumberParsingError.into())
}

/// Provide from/to Hex
pub trait Hex<T> {
	/// From Hex strong to Vec<u8> for example
	fn from_hex(str: &str) -> Result<T>;
	/// From Vec<u8> to Hex string
	fn to_hex(&self) -> String;
}

/// Address Bech32 string conversion
pub trait AddrBech32<T> {
	/// Convert from Bech32 address string
	fn from_bech32(bech32_str: &str) -> Result<T>;

	/// Convert from Bech32 address string, and check the HRP(Human Readable Part)
	fn from_bech32_check(bech32_str: &str, hrp_bytes: Vec<u8>) -> Result<T>;
	/// Convert from Bech32 address string, and return the HRP(Human Readable Part)
	fn from_bech32_check_raw(bech32_str: &str) -> Result<(T, Vec<u8>)>;

	/// Convert to Bech32 address string
	fn to_bech32(&self, hrp_bytes: Vec<u8>) -> String;
}

fn serialize_public_key(public_key: &PublicKey) -> Vec<u8> {
	let secp = Secp256k1::new();
	let ser = public_key.serialize_vec(&secp, true);
	ser[..].to_vec()
}

impl Hex<PublicKey> for PublicKey {
	fn from_hex(str: &str) -> Result<PublicKey> {
		let secp = Secp256k1::new();
		let hex = from_hex(str.to_string())?;
		PublicKey::from_slice(&secp, &hex).map_err(|_| ErrorKind::InvalidBech32Key.into())
	}

	fn to_hex(&self) -> String {
		to_hex(serialize_public_key(self))
	}
}

impl AddrBech32<PublicKey> for PublicKey {
	fn from_bech32(bech32_str: &str) -> Result<PublicKey> {
		let secp = Secp256k1::new();
		let addr = Bech32::from_string(bech32_str);
		if let Err(e) = addr {
			return Err(ErrorKind::Bech32Error(e).into());
		}
		PublicKey::from_slice(&secp, &addr.unwrap().data)
			.map_err(|_| ErrorKind::InvalidBech32Key.into())
	}

	fn from_bech32_check(bech32_str: &str, version_expect: Vec<u8>) -> Result<PublicKey> {
		let secp = Secp256k1::new();
		let addr = Bech32::from_string(bech32_str)?;
		if addr.hrp.into_bytes() != version_expect {
			return Err(ErrorKind::InvalidChainType.into());
		}
		PublicKey::from_slice(&secp, &addr.data).map_err(|_| ErrorKind::InvalidBech32Key.into())
	}

	fn from_bech32_check_raw(bech32_str: &str) -> Result<(PublicKey, Vec<u8>)> {
		let secp = Secp256k1::new();
		let addr = Bech32::from_string(bech32_str)?;
		let pub_key = PublicKey::from_slice(&secp, &addr.data);
		if let Err(_) = pub_key {
			return Err(ErrorKind::InvalidBech32Key.into());
		}
		Ok((pub_key.unwrap(), addr.hrp.into_bytes()))
	}

	fn to_bech32(&self, hrp_bytes: Vec<u8>) -> String {
		let b = Bech32 {
			hrp: String::from_utf8_lossy(&hrp_bytes).into_owned(),
			data: serialize_public_key(self),
		};
		b.to_string(true).unwrap()
	}
}

impl Hex<Signature> for Signature {
	fn from_hex(str: &str) -> Result<Signature> {
		let secp = Secp256k1::new();
		let hex = from_hex(str.to_string())?;
		Signature::from_der(&secp, &hex).map_err(|_| ErrorKind::SecpError.into())
	}

	fn to_hex(&self) -> String {
		let secp = Secp256k1::new();
		let signature = self.serialize_der(&secp);
		to_hex(signature)
	}
}

impl Hex<SecretKey> for SecretKey {
	fn from_hex(str: &str) -> Result<SecretKey> {
		let secp = Secp256k1::new();
		let data = from_hex(str.to_string())?;
		SecretKey::from_slice(&secp, &data).map_err(|_| ErrorKind::SecpError.into())
	}

	fn to_hex(&self) -> String {
		to_hex(self.0.to_vec())
	}
}

impl Hex<Commitment> for Commitment {
	fn from_hex(str: &str) -> Result<Commitment> {
		let data = from_hex(str.to_string())?;
		Ok(Commitment::from_vec(data))
	}

	fn to_hex(&self) -> String {
		to_hex(self.0.to_vec())
	}
}

pub fn public_key_from_secret_key(secret_key: &SecretKey) -> Result<PublicKey> {
	let secp = Secp256k1::new();
	PublicKey::from_secret_key(&secp, secret_key).map_err(|_| ErrorKind::SecpError.into())
}

pub fn sign_challenge(challenge: &str, secret_key: &SecretKey) -> Result<Signature> {
	let mut hasher = Sha256::new();
	hasher.input(challenge.as_bytes());
	let message = Message::from_slice(hasher.result().as_slice())?;
	let secp = Secp256k1::new();
	secp.sign(&message, secret_key)
		.map_err(|_| ErrorKind::SecpError.into())
}

pub fn verify_signature(
	challenge: &str,
	signature: &Signature,
	public_key: &PublicKey,
) -> Result<()> {
	let mut hasher = Sha256::new();
	hasher.input(challenge.as_bytes());
	let message = Message::from_slice(hasher.result().as_slice())?;
	let secp = Secp256k1::new();
	secp.verify(&message, signature, public_key)
		.map_err(|_| ErrorKind::SecpError.into())
}
