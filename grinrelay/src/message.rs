// Copyright 2018 The Vault713 Developers
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

//! Grin Relay Messages

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use rand::thread_rng;
use rand::Rng;
use ring::aead;
use ring::{digest, pbkdf2};
use secp256k1zkp::Secp256k1;

use crate::crypto::{from_hex, to_hex};
use crate::error::ErrorKind;
use crate::grinrelay_address::GrinboxAddress;
use crate::Result;

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
	pub destination: GrinboxAddress,
	pub encrypted_message: String,
	salt: String,
	nonce: String,
}

impl EncryptedMessage {
	pub fn new(
		message: String,
		destination: &GrinboxAddress,
		receiver_public_key: &PublicKey,
		secret_key: &SecretKey,
	) -> Result<EncryptedMessage> {
		let secp = Secp256k1::new();
		let mut common_secret = receiver_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| ErrorKind::Encryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let salt: [u8; 8] = thread_rng().gen();
		let nonce: [u8; 12] = thread_rng().gen();
		let mut key = [0; 32];
		pbkdf2::derive(&digest::SHA512, 10000, &salt, common_secret_slice, &mut key);
		let mut enc_bytes = message.as_bytes().to_vec();
		let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}
		let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key)
			.map_err(|_| ErrorKind::Encryption)?;
		aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
			.map_err(|_| ErrorKind::Encryption)?;

		Ok(EncryptedMessage {
			destination: destination.clone(),
			encrypted_message: to_hex(enc_bytes),
			salt: to_hex(salt.to_vec()),
			nonce: to_hex(nonce.to_vec()),
		})
	}

	pub fn key(&self, sender_public_key: &PublicKey, secret_key: &SecretKey) -> Result<[u8; 32]> {
		let salt = from_hex(self.salt.clone()).map_err(|_| ErrorKind::Decryption)?;

		let secp = Secp256k1::new();
		let mut common_secret = sender_public_key.clone();
		common_secret
			.mul_assign(&secp, secret_key)
			.map_err(|_| ErrorKind::Decryption)?;
		let common_secret_ser = common_secret.serialize_vec(&secp, true);
		let common_secret_slice = &common_secret_ser[1..33];

		let mut key = [0; 32];
		pbkdf2::derive(&digest::SHA512, 10000, &salt, common_secret_slice, &mut key);

		Ok(key)
	}

	pub fn decrypt_with_key(&self, key: &[u8; 32]) -> Result<String> {
		let mut encrypted_message =
			from_hex(self.encrypted_message.clone()).map_err(|_| ErrorKind::Decryption)?;
		let nonce = from_hex(self.nonce.clone()).map_err(|_| ErrorKind::Decryption)?;

		let opening_key = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, key)
			.map_err(|_| ErrorKind::Decryption)?;
		let decrypted_data =
			aead::open_in_place(&opening_key, &nonce, &[], 0, &mut encrypted_message)
				.map_err(|_| ErrorKind::Decryption)?;

		String::from_utf8(decrypted_data.to_vec()).map_err(|_| ErrorKind::Decryption.into())
	}

	pub fn get_decrypted_message(&self, key: &[u8; 32]) -> Result<DecryptedMessage> {
		Ok(DecryptedMessage {
			destination: self.destination.clone(),
			message: self.decrypt_with_key(key)?,
			salt: self.salt.clone(),
			nonce: self.nonce.clone(),
		})
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptedMessage {
	pub destination: GrinboxAddress,
	pub message: String,
	pub salt: String,
	pub nonce: String,
}

impl DecryptedMessage {
	pub fn encrypt_with_key(&self, key: &[u8; 32]) -> Result<EncryptedMessage> {
		let mut enc_bytes = self.message.as_bytes().to_vec();
		let suffix_len = aead::CHACHA20_POLY1305.tag_len();
		for _ in 0..suffix_len {
			enc_bytes.push(0);
		}
		let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, key)
			.map_err(|_| ErrorKind::Encryption)?;

		let nonce = from_hex(self.nonce.clone()).map_err(|_| ErrorKind::Encryption)?;
		aead::seal_in_place(&sealing_key, &nonce, &[], &mut enc_bytes, suffix_len)
			.map_err(|_| ErrorKind::Encryption)?;

		let encrypted_message = to_hex(enc_bytes);
		Ok(EncryptedMessage {
			destination: self.destination.clone(),
			encrypted_message,
			salt: self.salt.clone(),
			nonce: self.nonce.clone(),
		})
	}
}
