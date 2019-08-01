// Copyright 2019 Gary Yu
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

/// Grin Relay 'plugin' implementation
use crate::config::WalletConfig;
use crate::libwallet::Listener;
use crate::libwallet::{Error, ErrorKind, Slate, SlateVersion, VersionedSlate};
use crate::WalletCommAdapter;
use colored::*;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

const TTL: u16 = 10; // TODO: Pass this as a parameter

pub struct GrinrelayWalletCommAdapter {
	listener: Box<dyn Listener>,
	relay_rx: Receiver<Slate>,
}

impl GrinrelayWalletCommAdapter {
	/// Create
	pub fn new(
		listener: Box<dyn Listener>,
		relay_rx: Receiver<Slate>,
	) -> Box<dyn WalletCommAdapter> {
		Box::new(GrinrelayWalletCommAdapter { listener, relay_rx })
	}
}

impl WalletCommAdapter for GrinrelayWalletCommAdapter {
	fn supports_sync(&self) -> bool {
		true
	}

	fn send_tx_sync(&self, dest: &str, slate: &Slate) -> Result<Slate, Error> {
		debug!(
			"Posting transaction slate to {} via Grin Relay service",
			dest
		);
		let versioned_slate = VersionedSlate::into_version(slate.clone(), SlateVersion::V2);
		self.listener.publish(&versioned_slate, &dest.to_owned())?;

		// Wait for response from recipient via Grin Relay
		info!("Waiting for recipient to response ...");
		let mut cnt = 0;
		loop {
			match self.relay_rx.try_recv() {
				Ok(slate) => {
					return Ok(slate);
				}
				Err(TryRecvError::Disconnected) => {
					return Err(ErrorKind::ClientCallback(
						"TryRecvError::Disconnected".to_owned(),
					))?
				}
				Err(TryRecvError::Empty) => {}
			}
			cnt += 1;
			if cnt > TTL * 10 {
				return Err(ErrorKind::ClientCallback(format!(
					"{} from recipient. {}s timeout",
					"No response".bright_blue(),
					TTL
				)))?;
			}
			thread::sleep(Duration::from_millis(100));
		}
	}

	fn send_tx_async(&self, _dest: &str, _slate: &Slate) -> Result<(), Error> {
		unimplemented!();
	}

	fn receive_tx_async(&self, _params: &str) -> Result<Slate, Error> {
		unimplemented!();
	}

	fn listen(
		&self,
		_params: HashMap<String, String>,
		_config: WalletConfig,
		_passphrase: &str,
		_account: &str,
		_node_api_secret: Option<String>,
	) -> Result<(), Error> {
		unimplemented!();
	}
}
