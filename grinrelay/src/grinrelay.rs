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

//! Grin Relay Service

use chrono::prelude::Utc;
use std::net::ToSocketAddrs;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

use crate::grinrelay_address::GrinboxAddress;
use crate::libwallet::{Listener, VersionedSlate};
use crate::message::EncryptedMessage;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use url::Url;
use ws::util::TcpStream as WsTcpStream;
use ws::util::Token;
use ws::{
	connect, CloseCode, Error as WsError, ErrorKind as WsErrorKind, Handler, Handshake, Message,
	Result as WsResult, Sender,
};

use crate::crypto::{sign_challenge, Hex};
use crate::error::ErrorKind;
use crate::grin_util::secp::key::SecretKey;
use crate::grin_util::Mutex;
use crate::protocol::{ProtocolRequest, ProtocolResponse};
use crate::tx_proof::TxProof;
use crate::types::{CloseReason, Controller, Publisher, Subscriber, SubscriptionHandler};
use crate::Result;

const KEEPALIVE_TOKEN: Token = Token(1);
const KEEPALIVE_INTERVAL_MS: u64 = 30_000;

#[derive(Clone)]
pub struct GrinboxListener {
	pub address: GrinboxAddress,
	pub publisher: GrinboxPublisher,
	pub subscriber: GrinboxSubscriber,
	//  todo: JoinHandle can't clone
	//	pub handle: JoinHandle<()>,
}

impl Listener for GrinboxListener {
	fn address(&self) -> String {
		self.address.stripped()
	}

	fn publish(&self, slate: &VersionedSlate, to: &String) -> Result<()> {
		let address = GrinboxAddress::from_str(to)?;
		self.publisher.post_slate(slate, &address)
	}

	fn stop(self: Box<Self>) -> Result<()> {
		let s = *self;
		s.subscriber.stop();
		//		let _ = s.handle.join();
		Ok(())
	}

	fn box_clone(&self) -> Box<Listener> {
		Box::new((*self).clone())
	}
}

#[derive(Clone)]
pub struct GrinboxPublisher {
	address: GrinboxAddress,
	broker: GrinboxBroker,
	secret_key: SecretKey,
}

impl GrinboxPublisher {
	pub fn new(
		address: &GrinboxAddress,
		secret_key: &SecretKey,
		protocol_unsecure: bool,
	) -> Result<Self> {
		Ok(Self {
			address: address.clone(),
			broker: GrinboxBroker::new(protocol_unsecure)?,
			secret_key: secret_key.clone(),
		})
	}
}

impl Publisher for GrinboxPublisher {
	fn post_slate(&self, slate: &VersionedSlate, to: &GrinboxAddress) -> Result<()> {
		let to = GrinboxAddress::from_str(&to.to_string())?;
		self.broker
			.post_slate(slate, &to, &self.address, &self.secret_key)?;
		Ok(())
	}
}

#[derive(Clone)]
pub struct GrinboxSubscriber {
	address: GrinboxAddress,
	broker: GrinboxBroker,
	secret_key: SecretKey,
}

impl GrinboxSubscriber {
	pub fn new(publisher: &GrinboxPublisher) -> Result<Self> {
		Ok(Self {
			address: publisher.address.clone(),
			broker: publisher.broker.clone(),
			secret_key: publisher.secret_key.clone(),
		})
	}
}

impl Subscriber for GrinboxSubscriber {
	fn start<P>(&mut self, handler: Controller<P>) -> Result<()>
	where
		P: Publisher,
	{
		let _ = self.broker.select_server(&self.address);

		debug!("Subscriber start on address: {}", self.address.stripped());
		self.broker
			.subscribe(&self.address, &self.secret_key, handler)?;
		Ok(())
	}

	fn stop(&self) {
		self.broker.stop();
	}

	fn is_running(&self) -> bool {
		self.broker.is_running()
	}
}

#[derive(Clone)]
struct GrinboxBroker {
	inner: Arc<Mutex<Option<Sender>>>,
	protocol_unsecure: bool,
	pub selected_server: Option<SocketAddr>,
}

struct ConnectionMetadata {
	retries: u32,
	connected_at_least_once: bool,
}

impl ConnectionMetadata {
	pub fn new() -> Self {
		Self {
			retries: 0,
			connected_at_least_once: false,
		}
	}
}

impl GrinboxBroker {
	fn new(protocol_unsecure: bool) -> Result<Self> {
		Ok(Self {
			inner: Arc::new(Mutex::new(None)),
			protocol_unsecure,
			selected_server: None,
		})
	}

	fn post_slate(
		&self,
		slate: &VersionedSlate,
		to: &GrinboxAddress,
		from: &GrinboxAddress,
		secret_key: &SecretKey,
	) -> Result<()> {
		if !self.is_running() {
			return Err(ErrorKind::ClosedListener("grinrelay".to_string()).into());
		}

		let pkey = to.public_key()?;
		let skey = secret_key.clone();
		let message = EncryptedMessage::new(serde_json::to_string(&slate)?, &to, &pkey, &skey)
			.map_err(|_| WsError::new(WsErrorKind::Protocol, "could not encrypt slate!"))?;
		let message_ser = serde_json::to_string(&message)?;

		let mut challenge = String::new();
		challenge.push_str(&message_ser);

		let signature = sign_challenge(&challenge, secret_key)?.to_hex();
		let request = ProtocolRequest::PostSlate {
			from: from.stripped(),
			to: to.stripped(),
			str: message_ser,
			signature,
		};

		if let Some(ref sender) = *self.inner.lock() {
			sender
				.send(serde_json::to_string(&request).unwrap())
				.map_err(|_| ErrorKind::GenericError("failed posting slate!".to_string()).into())
		} else {
			Err(ErrorKind::GenericError("failed posting slate!".to_string()).into())
		}
	}

	// todo: move this 'select' logic into 'subscribe' function,
	// so as to have selection for each failure and retrying case.
	fn select_server(&mut self, address: &GrinboxAddress) -> Result<SocketAddr> {
		const NANO_TO_MILLIS: f64 = 1.0 / 1_000_000.0;

		let cloned_address = address.clone();
		let mut addresses: Vec<SocketAddr> = vec![];
		let addrs = (cloned_address.domain.as_str(), 0).to_socket_addrs()?;
		addresses.append(
			&mut (addrs
				.map(|mut addr| {
					addr.set_port(cloned_address.port() + 1);
					addr
				})
				.collect()),
		);

		let mut selected_addr = addresses[0];
		let mut min_rtt = 10_000f64;
		debug!("Start selecting on {} servers", addresses.len());
		for addr in addresses {
			let url = format!("{}", addr);

			let start = Utc::now().timestamp_nanos();
			let stream = TcpStream::connect(url);

			let fin = Utc::now().timestamp_nanos();
			let rtt_ms = (fin - start) as f64 * NANO_TO_MILLIS;
			match stream {
				Ok(_) => {
					if rtt_ms < min_rtt {
						min_rtt = rtt_ms;
						selected_addr = addr;
					}
					debug!("Select {} got rtt: {:.3}(ms)", addr, rtt_ms);
				}
				Err(e) => {
					error!(
						"Select {} failed on connect! fail on {:.0} seconds for {}",
						addr,
						rtt_ms / 1000f64,
						e,
					);
				}
			}
		}

		selected_addr.set_port(cloned_address.port());
		//todo: reverse dns to switch the ip address into domain again, for redundancy

		debug!("Server {} selected. rtt: {:.3}(ms)", selected_addr, min_rtt);
		self.selected_server = Some(selected_addr.clone());
		Ok(selected_addr)
	}

	fn subscribe<P>(
		&mut self,
		address: &GrinboxAddress,
		secret_key: &SecretKey,
		handler: Controller<P>,
	) -> Result<()>
	where
		P: Publisher,
	{
		let handler = Arc::new(Mutex::new(handler));
		let url = if let Some(selected_server) = self.selected_server {
			match self.protocol_unsecure {
				true => format!("ws://{}", selected_server),
				false => format!("wss://{}", selected_server),
			}
		} else {
			let cloned_address = address.clone();
			match self.protocol_unsecure {
				true => format!("ws://{}:{}", cloned_address.domain, cloned_address.port(),),
				false => format!("wss://{}:{}", cloned_address.domain, cloned_address.port(),),
			}
		};
		debug!("subscribe into {}", url);
		let cloned_address = address.clone();
		let cloned_inner = self.inner.clone();
		let cloned_handler = handler.clone();
		let connection_meta_data = Arc::new(Mutex::new(ConnectionMetadata::new()));
		loop {
			let cloned_address = cloned_address.clone();
			let cloned_handler = cloned_handler.clone();
			let cloned_cloned_inner = cloned_inner.clone();
			let cloned_connection_meta_data = connection_meta_data.clone();
			let result = connect(url.clone(), |sender| {
				{
					let mut guard = cloned_cloned_inner.lock();
					*guard = Some(sender.clone());
				}

				let client = GrinboxClient {
					sender,
					handler: cloned_handler.clone(),
					challenge: None,
					address: cloned_address.clone(),
					secret_key: secret_key.clone(),
					connection_meta_data: cloned_connection_meta_data.clone(),
				};
				client
			});

			let is_stopped = cloned_inner.lock().is_none();

			if is_stopped {
				match result {
					Err(_) => {
						error!("websocket abnormal termination");
						handler.lock().on_close(CloseReason::Abnormal)
					}
					_ => handler.lock().on_close(CloseReason::Normal),
				}
				break;
			} else {
				let mut guard = connection_meta_data.lock();
				if guard.retries == 0 && guard.connected_at_least_once {
					handler.lock().on_dropped();
				}
				let secs = std::cmp::min(32, 2u64.pow(guard.retries));
				let duration = std::time::Duration::from_secs(secs);
				std::thread::sleep(duration);
				guard.retries += 1;
			}
		}
		let mut guard = cloned_inner.lock();
		*guard = None;
		Ok(())
	}

	fn stop(&self) {
		let mut guard = self.inner.lock();
		if let Some(ref sender) = *guard {
			if let Err(e) = sender.close(CloseCode::Normal) {
				error!("GrinboxBroker::stop failed for {}", e);
			}
		}
		*guard = None;
	}

	fn is_running(&self) -> bool {
		let guard = self.inner.lock();
		guard.is_some()
	}
}

struct GrinboxClient<P>
where
	P: Publisher,
{
	sender: Sender,
	handler: Arc<Mutex<Controller<P>>>,
	challenge: Option<String>,
	address: GrinboxAddress,
	secret_key: SecretKey,
	connection_meta_data: Arc<Mutex<ConnectionMetadata>>,
}

impl<P> GrinboxClient<P>
where
	P: Publisher,
{
	fn subscribe(&self, challenge: &str) -> Result<()> {
		let signature = sign_challenge(&challenge, &self.secret_key)?.to_hex();
		let request = ProtocolRequest::Subscribe {
			address: self.address.public_key.to_string(),
			signature,
		};
		self.send(&request)
			.expect("could not send subscribe request!");
		Ok(())
	}

	fn send(&self, request: &ProtocolRequest) -> Result<()> {
		let request = serde_json::to_string(&request).unwrap();
		self.sender.send(request)?;
		Ok(())
	}
}

impl<P> Handler for GrinboxClient<P>
where
	P: Publisher,
{
	fn on_open(&mut self, _shake: Handshake) -> WsResult<()> {
		let mut guard = self.connection_meta_data.lock();

		if guard.connected_at_least_once {
			self.handler.lock().on_reestablished();
		} else {
			self.handler.lock().on_open();
			guard.connected_at_least_once = true;
		}

		guard.retries = 0;

		self.sender
			.timeout(KEEPALIVE_INTERVAL_MS, KEEPALIVE_TOKEN)?;
		Ok(())
	}

	fn on_message(&mut self, msg: Message) -> WsResult<()> {
		let response = match serde_json::from_str::<ProtocolResponse>(&msg.to_string()) {
			Ok(x) => x,
			Err(e) => {
				error!("Could not parse response. e = {}", e);
				return Ok(());
			}
		};

		match response {
			ProtocolResponse::Challenge { str } => {
				self.challenge = Some(str.clone());
				self.subscribe(&str).map_err(|_| {
					WsError::new(WsErrorKind::Protocol, "error attempting to subscribe!")
				})?;
			}
			ProtocolResponse::Slate {
				from,
				str,
				challenge,
				signature,
			} => {
				let (slate, mut tx_proof) = match TxProof::from_response(
					from,
					str,
					challenge,
					signature,
					&self.secret_key,
					Some(&self.address),
				) {
					Ok(x) => x,
					Err(e) => {
						error!("{}", e);
						return Ok(());
					}
				};

				let address = tx_proof.address.clone();
				self.handler
					.lock()
					.on_slate(&address, &slate, Some(&mut tx_proof));
			}
			ProtocolResponse::Error {
				kind: _,
				description: _,
			} => {
				error!("{}", response);
			}
			_ => {}
		}
		Ok(())
	}

	fn on_error(&mut self, err: WsError) {
		// Ignore connection reset errors by default
		if let WsErrorKind::Io(ref err) = err.kind {
			if let Some(104) = err.raw_os_error() {
				return;
			}
		}

		error!("{:?}", err);
	}

	fn on_timeout(&mut self, event: Token) -> WsResult<()> {
		match event {
			KEEPALIVE_TOKEN => {
				self.sender.ping(vec![])?;
				self.sender.timeout(KEEPALIVE_INTERVAL_MS, KEEPALIVE_TOKEN)
			}
			_ => Err(WsError::new(
				WsErrorKind::Internal,
				"Invalid timeout token encountered!",
			)),
		}
	}

	fn upgrade_ssl_client(
		&mut self,
		sock: WsTcpStream,
		url: &Url,
	) -> ws::Result<SslStream<WsTcpStream>> {
		debug!("upgrade_ssl_client: url = {}", url);
		let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| {
			ws::Error::new(
				ws::ErrorKind::Internal,
				format!("Failed to upgrade client to SSL: {}", e),
			)
		})?;
		builder.set_verify(SslVerifyMode::empty());

		let connector = builder.build();
		connector
			.configure()
			.unwrap()
			.use_server_name_indication(false)
			.verify_hostname(false)
			.connect("", sock)
			.map_err(From::from)
	}
}
