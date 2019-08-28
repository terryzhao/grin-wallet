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

//! Grin Relay Protocol

use colored::*;
use failure::Fail;
use std::fmt::{Display, Formatter, Result};

#[derive(Fail, Serialize, Deserialize, Debug)]
pub enum ProtocolError {
	#[fail(display = "GrinRelay Protocol: unknown error")]
	UnknownError,
	#[fail(display = "GrinRelay Protocol: invalid request")]
	InvalidRequest,
	#[fail(display = "GrinRelay Protocol: invalid signature")]
	InvalidSignature,
	#[fail(display = "GrinRelay Protocol: invalid challenge")]
	InvalidChallenge,
	#[fail(display = "GrinRelay Protocol: invalid relay abbr")]
	InvalidRelayAbbr,
	#[fail(display = "GrinRelay Protocol: too many subscriptions")]
	TooManySubscriptions,
	#[fail(display = "GrinRelay Protocol: not online")]
	Offline,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolRequest {
	Challenge,
	Subscribe {
		address: String,
		signature: String,
	},
	RetrieveRelayAddr {
		abbr: String,
	},
	PostSlate {
		from: String,
		to: String,
		str: String,
		signature: String,
	},
	Unsubscribe {
		address: String,
	},
}

impl Display for ProtocolRequest {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolRequest::Challenge => write!(f, "{}", "Challenge".bright_purple()),
			ProtocolRequest::Subscribe {
				ref address,
				signature: _,
			} => write!(
				f,
				"{} to {}",
				"Subscribe".bright_purple(),
				address.bright_green()
			),
			ProtocolRequest::Unsubscribe { ref address } => write!(
				f,
				"{} from {}",
				"Unsubscribe".bright_purple(),
				address.bright_green()
			),
			ProtocolRequest::PostSlate {
				ref from,
				ref to,
				str: _,
				signature: _,
			} => write!(
				f,
				"{} from {} to {}",
				"PostSlate".bright_purple(),
				from.bright_green(),
				to.bright_green()
			),
			ProtocolRequest::RetrieveRelayAddr { ref abbr } => write!(
				f,
				"{}: {}",
				"RetrieveRelayAddr".bright_purple(),
				abbr.bright_green()
			),
		}
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProtocolResponse {
	Ok,
	Error {
		kind: ProtocolError,
		description: String,
	},
	Challenge {
		str: String,
	},
	Slate {
		from: String,
		str: String,
		signature: String,
		challenge: String,
	},
	RelayAddr {
		abbr: String,
		relay_addr: Vec<String>,
	},
}

impl Display for ProtocolResponse {
	fn fmt(&self, f: &mut Formatter) -> Result {
		match *self {
			ProtocolResponse::Ok => write!(f, "{}", "Ok".cyan()),
			ProtocolResponse::Error {
				ref kind,
				description: _,
			} => write!(f, "{}: {}", "error".bright_red(), kind),
			ProtocolResponse::Challenge { ref str } => {
				write!(f, "{} {}", "Challenge".cyan(), str.bright_green())
			}
			ProtocolResponse::Slate {
				ref from,
				str: _,
				signature: _,
				challenge: _,
			} => write!(f, "{} from {}", "Slate".cyan(), from.bright_green()),
			ProtocolResponse::RelayAddr {
				ref abbr,
				ref relay_addr,
			} => write!(
				f,
				"{}:  abbr: {}, relay_addr: {}",
				"RelayAddr".cyan(),
				abbr,
				relay_addr[0]
			),
		}
	}
}
