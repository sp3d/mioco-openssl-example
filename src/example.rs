#![allow(deprecated)]

/*
mioco+openssl example which concurrently:

connects to a remote server (with the OpenSSL MaybeSslStream type) and also
runs a local server accepting TLS connections authenticated by client certificates

released under the WTFPL
*/

#[macro_use]
extern crate mioco;
extern crate openssl;

mod secure;

use std::sync::{Arc, Mutex};
use std::path::PathBuf;

use mioco::sync::mpsc::{Sender, Receiver, channel};

use openssl::ssl::{SslStream, MaybeSslStream};

/* example types for cross-coroutine messages */
struct CSEvent {}
struct SCEvent {}

pub struct ServerInfo {
	/* the hostname of the remote to connect to */
	remote_host: String,
	/* the port of the remote */
	remote_port: u16,
	/* whether to use TLS to connect to the remote */
	remote_use_tls: bool,

	/* the path to the cerificate expected from clients */
	client_cert_path: PathBuf,
	/* the port on which the local server listens */
	listen_port: u16,
	/* the path to the server's certificate */
	server_cert_path: PathBuf,
	/* the path to the private key used by the local server */
	server_privkey_path: PathBuf,
}

struct ClientList {
	clients: Vec<Sender<SCEvent>>,
}

enum ConnectionStatus {
	Closed,
	Open(MaybeSslStream<mioco::tcp::TcpStream>),
}

enum ConnectionAction {
	Reconnect,
	Communicate,
}

impl ClientList {
	fn connect_remote(spec: &ServerInfo) -> Option<MaybeSslStream<mioco::tcp::TcpStream>> {
		use std::net::ToSocketAddrs;
		match (&*spec.remote_host, spec.remote_port).to_socket_addrs() {
			Ok(addrs) => {
				let mut status2 = None;
				for addr in addrs {
					println!("attempting to connect to {}", addr);
					match mioco::tcp::TcpStream::connect(&addr) {
						Ok(conn) => {
							status2 = if spec.remote_use_tls {
								let ctx = secure::server_context(spec);
								match SslStream::connect(&ctx, conn) {
									Ok(sslstream) => Some(MaybeSslStream::Ssl(sslstream)),
									Err(e) => {
										println!("error connecting to server over ssl: {}", e);
										None
									},
								}
							} else {
								Some(MaybeSslStream::Normal(conn))
							};
							break
						},
						Err(e) => {
							println!("error connecting to server: {}", e);
							status2 = None
						},
					}
				}
				status2
			},
			Err(e) => {
				println!("unable to resolve host {}: {}", &*spec.remote_host, e);
				None
			}
		}
	}
	/* run the lifetime of the remote connection */
	fn handle_remote(client_to_server_rx: Receiver<CSEvent>, state_spec: Arc<(Mutex<ClientList>, ServerInfo)>) {
		use std::io::Read;
		let client_list = &state_spec.0;
		let spec = &state_spec.1;
		let mut failed_connects: usize = 0;
		let mut status = ConnectionStatus::Closed;

		let mut buf = vec![];
		loop {
			status = match status {
				ConnectionStatus::Closed => {
					/* sleep for an exponentially increasing amount with the # of consecutive failures */
					let ms = (1000.*(1.5f32.powi(failed_connects as i32)-1.)) as i32;
					if ms > 0 {
						println!("waiting for {} ms before attempting connection", ms);
						mioco::sleep_ms(ms as u64);
					};
					/* connect to the remote server */
					match ClientList::connect_remote(spec) {
						/* send autosay */
						Some(conn) => {
							failed_connects = 0;
							ConnectionStatus::Open(conn)
						},
						None => {
							failed_connects += 1;
							ConnectionStatus::Closed
						}
					}
				},
				ConnectionStatus::Open(mut conn) => {
					/* handle an open connection */
					let mut action = ConnectionAction::Communicate;
					let conn_inner = conn.get_mut().try_clone().unwrap();
					select!(
						r:conn_inner => {
							match conn.read(&mut buf) {
								Ok(bytes_read) => {
									/* handle read data */

									/* write to @conn or dump messages into a channel in @client_list */
								},
								Err(e) => {
									println!("error reading from server: {}", e);
									action=ConnectionAction::Reconnect
								},
							}
						},
						r:client_to_server_rx => {
							match client_to_server_rx.recv() {
								Ok(_event) => {
									/* handle cross-coroutine messages */

									/* write to @conn or dump messages into a channel in @client_list */
								},
								Err(e) => {
									println!("error reading event from thread: {}", e);
								}
							};
						},
					); match action {
						ConnectionAction::Communicate => ConnectionStatus::Open(conn),
						ConnectionAction::Reconnect => ConnectionStatus::Closed,
					}
				},
			}
		}
	}
	/* run the lifetime of a client */
	fn handle_client(conn: mioco::tcp::TcpStream, wakeup_chan: Receiver<SCEvent>, client_to_server_tx: Sender<CSEvent>, state_spec: Arc<(Mutex<ClientList>, ServerInfo)>) {
		use std::io::Read;
		let client_list = &state_spec.0;
		let spec = &state_spec.1;

		/* shadow our TCP connection with an SSL connection */
		let mut conn = {
			let ctx = secure::client_context(spec);
			SslStream::accept(&ctx, conn).expect("failed to create SSL client")
		};

		let mut buf = vec![];
		/* mioco has to watch for readiness on the inner TCP stream */
		let conn_inner = conn.get_mut().try_clone().unwrap();
		loop {
		select!(
			r:conn_inner => {
				match conn.read(&mut buf) {
					Ok(bytes_read) => {
						/* handle read bytes */

						/* write to @conn or dump messages into @client_to_server_tx or a channel in @client_list */

						/* a read of 0 bytes means the connection has been closed */
						if bytes_read == 0 {
							break
						}
					},
					Err(e) => {
						println!("error reading from client: {}", e);
						break
					}
				}
			},
			r:wakeup_chan => {
				/* write to @conn or dump messages into @client_to_server_tx or a channel in @client_list */
			},
		);
		}
	}
	fn accept_clients(client_to_server_tx: Sender<CSEvent>, state_spec: Arc<(Mutex<ClientList>, ServerInfo)>) -> () {
		use std::net::ToSocketAddrs;

		let state = &state_spec.0;
		let spec = &state_spec.1;

		let mut addrs = ("0.0.0.0", spec.listen_port).to_socket_addrs().expect("could not convert 0.0.0.0 to socket address");
		let addr = addrs.next().expect("no host addresses for ip 0.0.0.0?");
		let listener = mioco::tcp::TcpListener::bind(&addr).expect("couldn't bind listening socket?");
		loop {
			match listener.accept() {
				Ok(tcpstream) => {
					println!("accepted connection from {}", tcpstream.peer_addr().unwrap());

					let (server_to_client_tx, server_to_client_rx) = channel::<SCEvent>();
					let client_to_server_tx = client_to_server_tx.clone();

					/* add it to the server's list so the server can send events to this thread */
					state.lock().expect("poisoned mutex").clients.push(server_to_client_tx);

					/* spawn a coroutine to handle it */
					let state_spec = state_spec.clone();
					mioco::spawn(move || ClientList::handle_client(tcpstream, server_to_client_rx, client_to_server_tx, state_spec));
				},
				Err(err) => println!("error accepting client: {}", err),
			};
		}
	}
}

fn main() {
	let specs = vec![ServerInfo {
		listen_port: 12345u16,
		remote_host: "localhost".into(),
		remote_port: 54321u16,
		remote_use_tls: true,
		client_cert_path: "/tmp/client_cert.crt".into(),
		server_cert_path: "/tmp/server_cert.crt".into(),
		server_privkey_path: "/tmp/server.key".into(),
	}];

	mioco::start(move || {
		for spec in specs {
			let state = Mutex::new(ClientList {
				clients: vec![],
			});

			let (client_to_server_tx, client_to_server_rx) = channel::<CSEvent>();

			let state_spec_1 = Arc::new((state, spec));
			let state_spec_2 = state_spec_1.clone();

			/* spawn coroutine to connect to the server */
			mioco::spawn(move || ClientList::handle_remote(client_to_server_rx, state_spec_1));
			/* spawn coroutine to handle incoming connections; this thread will spawn a coroutine for each of those */
			mioco::spawn(move || ClientList::accept_clients(client_to_server_tx, state_spec_2));
		}
	}).expect("mioco error");
}
