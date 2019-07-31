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

//! Grin Relay Types

use colored::*;

use crate::grin_core::core::amount_to_hr_string;
use crate::grinrelay_address::GrinboxAddress;
use crate::libwallet::{Slate, VersionedSlate};
use crate::tx_proof::TxProof;
use crate::ErrorKind;
use crate::Result;
use std::sync::mpsc::Sender;

pub enum CloseReason {
	Normal,
	Abnormal,
}

pub trait Publisher: Send {
	fn post_slate(&self, slate: &VersionedSlate, to: &GrinboxAddress) -> Result<()>;
}

pub trait Subscriber {
	fn start<P>(&mut self, handler: Controller<P>) -> Result<()>
	where
		P: Publisher;
	fn stop(&self);
	fn is_running(&self) -> bool;
}

pub trait SubscriptionHandler: Send {
	fn on_open(&self);
	fn on_slate(&self, from: &GrinboxAddress, slate: &VersionedSlate, proof: Option<&mut TxProof>);
	fn on_close(&self, result: CloseReason);
	fn on_dropped(&self);
	fn on_reestablished(&self);
}

#[allow(dead_code)]
pub struct Controller<P>
where
	P: Publisher,
{
	name: String,
	publisher: P,
	relay_tx_as_payer: Option<Sender<Slate>>,
	relay_tx_as_payee: Option<Sender<(String, Slate)>>,
}

impl<P> Controller<P>
where
	P: Publisher,
{
	pub fn new(
		name: &str,
		publisher: P,
		relay_tx_as_payer: Option<Sender<Slate>>,
		relay_tx_as_payee: Option<Sender<(String, Slate)>>,
	) -> Result<Self> {
		Ok(Self {
			name: name.to_string(),
			publisher,
			relay_tx_as_payer,
			relay_tx_as_payee,
		})
	}

	fn process_incoming_slate(
		&self,
		address: String,
		slate: &mut Slate,
		_tx_proof: Option<&mut TxProof>,
	) -> Result<()> {
		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().len() == 0 {
				// TODO: invoicing
			} else {
				debug!(
					"process_incoming_slate: slate [{}] received from {}",
					slate.id.to_string().bright_green(),
					address.bright_green(),
				);
				//*slate = self.foreign.receive_tx(slate, None, address, None)?;
				if self.relay_tx_as_payee.is_some() {
					let _ = self
						.relay_tx_as_payee
						.clone()
						.unwrap()
						.send((address, slate.clone()));
				} else {
					return Err(ErrorKind::GenericError(
						"relay mspc sender (as payee) missed".to_string(),
					)
					.into());
				}
			}
			Ok(())
		} else {
			debug!(
				"process_incoming_slate: slate [{}] received from {}",
				slate.id.to_string().bright_green(),
				address.bright_green(),
			);
			//self.owner.finalize_tx(slate, tx_proof)?;
			if self.relay_tx_as_payer.is_some() {
				let _ = self.relay_tx_as_payer.clone().unwrap().send(slate.clone());
				Ok(())
			} else {
				Err(
					ErrorKind::GenericError("relay mspc sender (as payer) missed".to_string())
						.into(),
				)
			}
		}
	}
}

impl<P> SubscriptionHandler for Controller<P>
where
	P: Publisher,
{
	fn on_open(&self) {
		info!(
			"Grin Relay listener started. Also ready to receive Grin at {}",
			self.name.bright_green()
		);
	}

	fn on_slate(
		&self,
		from: &GrinboxAddress,
		slate: &VersionedSlate,
		tx_proof: Option<&mut TxProof>,
	) {
		let mut slate: Slate = slate.clone().into();

		if slate.num_participants > slate.participant_data.len() {
			info!(
				"Slate [{}] received from [{}] for [{}] grins",
				slate.id.to_string().bright_green(),
				from.stripped().bright_green(),
				amount_to_hr_string(slate.amount, true).bright_green(),
			);
		} else {
			info!(
				"Slate [{}] received back from [{}] for [{}] grins",
				slate.id.to_string().bright_green(),
				from.stripped().bright_green(),
				amount_to_hr_string(slate.amount, true).bright_green(),
			);
		};

		GrinboxAddress::from_str(&from.to_string()).expect("invalid grinrelay address");

		let result = self.process_incoming_slate(from.stripped(), &mut slate, tx_proof);

		match result {
			Ok(_) => {}
			Err(e) => error!("{}", e),
		}
	}

	fn on_close(&self, reason: CloseReason) {
		match reason {
			CloseReason::Normal => info!("Listener for {} stopped", self.name.bright_green()),
			CloseReason::Abnormal => {
				info!("Listener {} stopped unexpectedly", self.name.bright_green())
			}
		}
	}

	fn on_dropped(&self) {
		info!("Listener {} lost connection. it will keep trying to restore connection in the background.", self.name.bright_green())
	}

	fn on_reestablished(&self) {
		info!(
			"Listener {} reestablished connection.",
			self.name.bright_green(),
		)
	}
}
