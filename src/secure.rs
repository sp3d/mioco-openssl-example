use openssl::ssl::SslContext;
use openssl::x509::{X509, X509StoreContext, X509FileType};
use openssl::ssl;

/* returns true if the cert received from the remote side is valid and present in `expected` */
fn verify_cert<'a>(_preverify_ok: bool, received_cert: &X509StoreContext, expected: &Vec<X509<'a>>) -> bool {
	/*if !preverify_ok {
		println!("precheck false");
		return false
	}*/
	match received_cert.get_current_cert() {
		Some(received_x509) => {
			let mut received_pem = Vec::with_capacity(2048);
			if let Err(e) = received_x509.write_pem(&mut received_pem) {
				println!("error verifying certificate: error converting received cert to PEM: {}", e);
				return false
			};
			expected.iter().any(|expected| {
				let mut expected_pem = Vec::with_capacity(2048);
				if let Err(e) = expected.write_pem(&mut expected_pem) {
					println!("error verifying certificate: error converting expected cert to PEM: {}", e);
					return false
				};
				&*received_pem == &*expected_pem
			})
		}
		None => {
			match received_cert.get_error() {
				Some(e) => println!("error verifying certificate: {}", "(https://github.com/sfackler/rust-openssl/issues/352)"),
				None => println!("error verifying certificate: no certificate provided"),
			};
			return false
		}
	}
}

/* return a context that can accept a client connection */
pub fn client_context(spec: &super::ServerInfo) -> SslContext {
	let mut ctx = ssl::SslContext::new(ssl::SslMethod::Tlsv1_2).expect("failed to create SSL context to accept client");
	ctx.set_cipher_list("DEFAULT").expect("failed to set cipher suite to \"DEFAULT\"");
	ctx.set_certificate_file(&*spec.server_cert_path, X509FileType::PEM).expect("failed to load server certificate");
	ctx.set_private_key_file(&*spec.server_privkey_path, X509FileType::PEM).expect("failed to load server private key");
	ctx.check_private_key().expect("private key validation failed");
	/* attach the client certificate to send */
	let mut client_cert_file = ::std::fs::File::open(&*spec.client_cert_path).expect("failed to open client certificate file");
	let expected = X509::from_pem(&mut client_cert_file).expect("failed to load client certificate");
	ctx.set_verify_with_data(ssl::SSL_VERIFY_PEER|ssl::SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_cert as fn(bool, &X509StoreContext, &Vec<X509>) -> bool, vec![expected]);
	ctx
}


/* return a context that can make a server connection */
pub fn server_context(spec: &super::ServerInfo) -> SslContext {
	let mut ctx = ssl::SslContext::new(ssl::SslMethod::Sslv23).expect("failed to create SSL context to connect to server");
	ctx.set_cipher_list("DEFAULT").expect("failed to set cipher suite to \"DEFAULT\"");
	ctx.set_verify(ssl::SSL_VERIFY_NONE, None);
	/* set the certificate to use */
	ctx.set_certificate_file(&*spec.server_cert_path, X509FileType::PEM).expect("failed to load server certificate");
	ctx.set_private_key_file(&*spec.server_privkey_path, X509FileType::PEM).expect("failed to load server private key");
	ctx.check_private_key().expect("private key validation failed");
	ctx
}
