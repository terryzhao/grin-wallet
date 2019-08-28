// Copyright 2019 The Gotts Developers
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

//! Higher level wallet functions which can be used by callers to operate
//! on the wallet, as well as helpers to invoke and instantiate wallets
//! and listeners

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate colored;
extern crate serde;

pub mod bech32;
pub mod crypto;
pub mod error;
pub mod grinrelay;
pub mod grinrelay_address;
pub mod hasher;
pub mod message;
pub mod protocol;
pub mod tx_proof;
pub mod types;

use crate::grin_util::secp::key::{PublicKey, SecretKey};
use secp256k1zkp::pedersen::Commitment;
use secp256k1zkp::{Message, Secp256k1, Signature};

use grin_wallet_libwallet as libwallet;
use grin_wallet_util::grin_core;
use grin_wallet_util::grin_util;

pub use crate::crypto::{sign_challenge, verify_signature};
pub use crate::error::ErrorKind;
pub use crate::grinrelay::{GrinboxListener, GrinboxPublisher, GrinboxSubscriber};
pub use crate::grinrelay_address::GrinboxAddress;
pub use crate::tx_proof::TxProofImpl;
pub use crate::types::{CloseReason, Controller, Publisher, Subscriber, SubscriptionHandler};

pub use failure::Error;
pub type Result<T> = std::result::Result<T, Error>;
