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
use crate::libwallet::TxProof;
use crate::libwallet::{Slate, VersionedSlate};
use crate::ErrorKind;
use crate::Result;
use std::sync::mpsc::Sender;

pub enum CloseReason {
	Normal,
	Abnormal,
}

pub trait Publisher: Send {
	fn retrieve_relay_addr(&self, abbr: String) -> Result<()>;
	fn post_slate(&self, slate: &VersionedSlate, to: &GrinboxAddress) -> Result<()>;
	fn is_connected(&self) -> bool;
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
	fn on_slate(&self, from: &str, slate: &VersionedSlate, proof: Option<TxProof>);
	fn on_relayaddr(&self, abbr: &str, fullname: Vec<String>);
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
	relay_tx_as_payer: Option<Sender<(Slate, Option<TxProof>)>>,
	relay_tx_as_payee: Option<Sender<(String, Slate)>>,
	relay_addr_query: Option<Sender<(String, Vec<String>)>>,
}

impl<P> Controller<P>
where
	P: Publisher,
{
	pub fn new(
		name: &str,
		publisher: P,
		relay_tx_as_payer: Option<Sender<(Slate, Option<TxProof>)>>,
		relay_tx_as_payee: Option<Sender<(String, Slate)>>,
		relay_addr_query: Option<Sender<(String, Vec<String>)>>,
	) -> Result<Self> {
		Ok(Self {
			name: name.to_string(),
			publisher,
			relay_tx_as_payer,
			relay_tx_as_payee,
			relay_addr_query,
		})
	}

	fn process_incoming_slate(
		&self,
		address: String,
		slate: &mut Slate,
		tx_proof: Option<TxProof>,
	) -> Result<()> {
		if slate.num_participants > slate.participant_data.len() {
			if slate.tx.inputs().len() == 0 {
				// TODO: invoicing
			} else {
				// as transaction recipient
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
						"relay mpsc sender (as payee) missed".to_string(),
					)
					.into());
				}
			}
			Ok(())
		} else {
			// as transaction sender/payer
			debug!(
				"process_incoming_slate: slate [{}] received from {}",
				slate.id.to_string().bright_green(),
				address.bright_green(),
			);
			//self.owner.finalize_tx(slate, tx_proof)?;
			if self.relay_tx_as_payer.is_some() {
				let _ = self
					.relay_tx_as_payer
					.clone()
					.unwrap()
					.send((slate.clone(), tx_proof));
				Ok(())
			} else {
				debug!("process_incoming_slate: relay mpsc sender (as payer) missed.");
				Err(ErrorKind::GenericError(
					"an obsoleted transaction slate received, ignored".to_string(),
				)
				.into())
			}
		}
	}

	fn process_resp_relayaddr(&self, abbr: &str, fullname: Vec<String>) {
		if self.relay_addr_query.is_some() {
			let _ = self
				.relay_addr_query
				.clone()
				.unwrap()
				.send((abbr.to_owned(), fullname.clone()));
		} else {
			debug!("process_resp_relayaddr: relay mpsc sender (relay addr query) missed.");
		}
	}
}

impl<P> SubscriptionHandler for Controller<P>
where
	P: Publisher,
{
	fn on_open(&self) {
		info!(
			"Grin Relay listener started on addr: {}",
			self.name.bright_green()
		);
	}

	fn on_slate(&self, from: &str, slate: &VersionedSlate, tx_proof: Option<TxProof>) {
		let mut slate: Slate = slate.clone().into();

		if slate.num_participants > slate.participant_data.len() {
			info!(
				"Slate [{}] received from [{}] for [{}] grins",
				slate.id.to_string().bright_green(),
				from.bright_green(),
				amount_to_hr_string(slate.amount, true).bright_green(),
			);
		} else {
			info!(
				"Slate [{}] received back from [{}] for [{}] grins",
				slate.id.to_string().bright_green(),
				from.bright_green(),
				amount_to_hr_string(slate.amount, true).bright_green(),
			);
		};

		let result = self.process_incoming_slate(from.to_owned(), &mut slate, tx_proof);

		match result {
			Ok(_) => {}
			Err(e) => error!("{}", e),
		}
	}

	fn on_relayaddr(&self, abbr: &str, fullname: Vec<String>) {
		self.process_resp_relayaddr(abbr, fullname);
	}

	fn on_close(&self, reason: CloseReason) {
		let len = self.name.len().saturating_sub(6);
		match reason {
			CloseReason::Normal => {
				info!("Listener for {} stopped", self.name[len..].bright_green())
			}
			CloseReason::Abnormal => info!(
				"Listener {} stopped unexpectedly",
				self.name[len..].bright_green()
			),
		}
	}

	fn on_dropped(&self) {
		let len = self.name.len().saturating_sub(6);
		info!("Listener {} lost connection. it will keep trying to restore connection in the background.", self.name[len..].bright_green())
	}

	fn on_reestablished(&self) {
		let len = self.name.len().saturating_sub(6);
		info!(
			"Listener {} reestablished connection.",
			self.name[len..].bright_green(),
		)
	}
}
