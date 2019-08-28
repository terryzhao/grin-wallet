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

//! Grin Relay Tx Proof

use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::secp::Signature;
use crate::Result;
use failure::Fail;

use crate::crypto::verify_signature;
use crate::crypto::Hex;
use crate::libwallet::{TxProof, VersionedSlate};
use crate::message::{DecryptedMessage, EncryptedMessage};
use crate::GrinboxAddress;

#[derive(Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Unable to parse address")]
	ParseAddress,
	#[fail(display = "Unable to parse public key")]
	ParsePublicKey,
	#[fail(display = "Unable to parse signature")]
	ParseSignature,
	#[fail(display = "Unable to verify signature")]
	VerifySignature,
	#[fail(display = "Unable to parse encrypted message")]
	ParseEncryptedMessage,
	#[fail(display = "Unable to verify destination")]
	VerifyDestination,
	#[fail(display = "Unable to determine decryption key")]
	DecryptionKey,
	#[fail(display = "Unable to decrypt message")]
	DecryptMessage,
	#[fail(display = "Unable to parse slate")]
	ParseSlate,
}

/// TxProof Implementation
pub trait TxProofImpl {
	/// Verify the Msg(message||challenge), PubKey(sender_address), and the Signature.
	fn verify_extract(&self, expected_destination: String) -> Result<VersionedSlate>;

	/// Get the Slate and TxProof from the recipient's response message
	fn from_response(
		from: String,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: String,
	) -> Result<(VersionedSlate, TxProof)>;
}

impl TxProofImpl for TxProof {
	/// Verify the Msg(message||challenge), PubKey(sender_address), and the Signature.
	fn verify_extract(&self, expected_destination: String) -> Result<VersionedSlate> {
		let decrypted_message: DecryptedMessage =
			serde_json::from_str(&self.message).map_err(|_| ErrorKind::ParseEncryptedMessage)?;
		let encrypted_message = decrypted_message.encrypt_with_key(&self.key)?;
		let encrypted_message = serde_json::to_string(&encrypted_message)?;

		let mut challenge = String::new();
		challenge.push_str(encrypted_message.as_str());
		challenge.push_str(self.challenge.as_str());

		let recipient_address = GrinboxAddress::from_str(self.recipient_address.as_str())
			.map_err(|_| ErrorKind::ParseAddress)?;

		let recipient_public_key = recipient_address
			.public_key()
			.map_err(|_| ErrorKind::ParsePublicKey)?;

		verify_signature(&challenge, &self.signature, &recipient_public_key)
			.map_err(|_| ErrorKind::VerifySignature)?;

		if !expected_destination.is_empty() {
			let expected_dest = GrinboxAddress::from_str(&expected_destination)
				.map_err(|_| ErrorKind::ParseAddress)?;

			let destination = decrypted_message.destination.clone();
			if destination.public_key != expected_dest.public_key {
				return Err(ErrorKind::VerifyDestination.into());
			}

			let sender_address = GrinboxAddress::from_str(&self.sender_address)
				.map_err(|_| ErrorKind::ParseAddress)?;
			if sender_address.public_key != expected_dest.public_key {
				return Err(ErrorKind::VerifyDestination.into());
			}
		}

		// Check prover's signature on the prover message
		if let Some(ref prover_msg) = self.prover_msg {
			if let Some(ref signature) = self.prover_signature {
				let sender_address = GrinboxAddress::from_str(&self.sender_address)
					.map_err(|_| ErrorKind::ParseAddress)?;

				verify_signature(prover_msg, signature, &sender_address.public_key()?)
					.map_err(|_| ErrorKind::VerifySignature)?;
				info!(
					"signature verification ok for prover's message: {}",
					prover_msg
				);
			} else {
				return Err(ErrorKind::VerifySignature.into());
			}
		}

		let slate: VersionedSlate =
			serde_json::from_str(&decrypted_message.message).map_err(|_| ErrorKind::ParseSlate)?;

		Ok(slate)
	}

	/// Get the Slate and TxProof from the recipient's response message
	fn from_response(
		from: String,
		message: String,
		challenge: String,
		signature: String,
		secret_key: &SecretKey,
		expected_destination: String,
	) -> Result<(VersionedSlate, TxProof)> {
		let recipient_address =
			GrinboxAddress::from_str(from.as_str()).map_err(|_| ErrorKind::ParseAddress)?;
		let signature =
			Signature::from_hex(signature.as_str()).map_err(|_| ErrorKind::ParseSignature)?;
		let recipient_public_key = recipient_address
			.public_key()
			.map_err(|_| ErrorKind::ParsePublicKey)?;
		let encrypted_message: EncryptedMessage =
			serde_json::from_str(&message).map_err(|_| ErrorKind::ParseEncryptedMessage)?;
		let key = encrypted_message
			.key(&recipient_public_key, secret_key)
			.map_err(|_| ErrorKind::DecryptionKey)?;

		let destination = encrypted_message.destination.clone();
		let sender_address = destination.stripped();

		let decrypted_message = encrypted_message
			.get_decrypted_message(&key)
			.map_err(|_| ErrorKind::DecryptMessage)?;

		let slate: VersionedSlate =
			serde_json::from_str(&decrypted_message.message).map_err(|_| ErrorKind::ParseSlate)?;

		let proof = TxProof {
			recipient_address: from,
			sender_address,
			message: serde_json::to_string(&decrypted_message)?,
			challenge,
			signature,
			key,
			amount: 0,
			fee: 0,
			inputs: vec![],
			outputs: vec![],
			prover_msg: None,
			prover_signature: None,
		};

		let _ = proof.verify_extract(expected_destination)?;

		Ok((slate, proof))
	}
}
