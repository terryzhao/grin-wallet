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

//! Grin Relay Errors

use crate::bech32::CodingError;
use failure::Fail;

#[derive(Clone, Debug, Eq, Fail, PartialEq, Serialize, Deserialize)]
pub enum ErrorKind {
	#[fail(display = "{}", 0)]
	GenericError(String),
	#[fail(display = "secp error")]
	SecpError,
	#[fail(display = "invalid chain type!")]
	InvalidChainType,
	#[fail(display = "invalid key!")]
	InvalidBech32Key,
	#[fail(display = "could not parse number from string!")]
	NumberParsingError,
	#[fail(display = "could not parse `{}` to a grinrelay address!", 0)]
	GrinboxAddressParsingError(String),
	#[fail(display = "unable to encrypt message")]
	Encryption,
	#[fail(display = "unable to decrypt message")]
	Decryption,
	#[fail(display = "unable to verify proof")]
	VerifyProof,
	#[fail(display = "grinrelay websocket terminated unexpectedly!")]
	GrinboxWebsocketAbnormalTermination,
	#[fail(display = "bech32 coding error `{}`", 0)]
	Bech32Error(CodingError),
	#[fail(display = "Listener for {} closed", 0)]
	ClosedListener(String),
}
