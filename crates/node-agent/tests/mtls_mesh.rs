use std::net::SocketAddr;
use std::sync::{Arc, Once, RwLock};
use std::time::Duration;

static INIT: Once = Once::new();

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

/// Hot-swappable certificate resolver used by the test server to emulate
/// on-the-fly rotation without dropping active connections.
#[derive(Clone, Debug)]
struct HotCertResolver {
    current: Arc<RwLock<Arc<rustls::sign::CertifiedKey>>>,
}

impl HotCertResolver {
    fn new(initial: Arc<rustls::sign::CertifiedKey>) -> Self {
        Self {
            current: Arc::new(RwLock::new(initial)),
        }
    }

    fn swap(&self, next: Arc<rustls::sign::CertifiedKey>) {
        let mut guard = self.current.write().expect("cert write lock");
        *guard = next;
    }
}

impl ResolvesServerCert for HotCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.current.read().expect("cert read lock").clone())
    }
}

fn make_ca() -> rcgen::Certificate {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    rcgen::Certificate::from_params(params).expect("ca params")
}

fn make_leaf(
    ca: &rcgen::Certificate,
    dns: &str,
) -> (
    rustls::sign::CertifiedKey,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let mut params = CertificateParams::default();
    params.subject_alt_names = vec![SanType::DnsName(dns.to_string())];
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, dns);
    let kp = KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("keypair");
    params.key_pair = Some(kp);
    let cert = rcgen::Certificate::from_params(params).expect("leaf params");

    let der = cert.serialize_der_with_signer(ca).expect("sign leaf der");
    let key_der = cert.serialize_private_key_der();

    let cert_der = CertificateDer::from(der.clone());
    let key_pem_der = PrivateKeyDer::try_from(key_der.clone()).expect("parse private key");

    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&key_pem_der).expect("signing key");
    let certified = rustls::sign::CertifiedKey::new(vec![cert_der.clone()], signing_key);

    (certified, cert_der, key_pem_der)
}

fn root_store(ca: &rcgen::Certificate) -> RootCertStore {
    let mut store = RootCertStore::empty();
    let ca_der = ca.serialize_der().expect("ca der");
    store
        .add(CertificateDer::from(ca_der))
        .expect("add ca to store");
    store
}

fn client_config(
    ca: &RootCertStore,
    client_cert: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(ca.clone())
        .with_client_auth_cert(client_cert, client_key)
        .expect("client auth cert");
    cfg.alpn_protocols.push(b"h2".to_vec());
    cfg.alpn_protocols.push(b"http/1.1".to_vec());
    Arc::new(cfg)
}

fn server_config(resolver: HotCertResolver, client_roots: RootCertStore) -> Arc<ServerConfig> {
    let verifier = WebPkiClientVerifier::builder(client_roots.into())
        .build()
        .expect("client verifier");
    Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(resolver)),
    )
}

async fn start_echo_server(config: Arc<ServerConfig>) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("listener addr");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let acceptor = TlsAcceptor::from(config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { continue; };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let mut tls = match acceptor.accept(stream).await {
                            Ok(t) => t,
                            Err(_) => return,
                        };
                        let mut buf = [0u8; 64];
                        loop {
                            match tls.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    if tls.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                }
            }
        }
    });

    (addr, shutdown_tx)
}

async fn connect_and_echo(
    connector: &TlsConnector,
    addr: SocketAddr,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost".to_owned()).expect("server name");
    let mut tls = connector.connect(server_name, tcp).await?;
    tls.write_all(message).await?;
    tls.flush().await?;
    let mut buf = vec![0u8; message.len()];
    tls.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn connect_stream(
    connector: &TlsConnector,
    addr: SocketAddr,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost".to_owned()).expect("server name");
    Ok(connector.connect(server_name, tcp).await?)
}

#[tokio::test]
async fn mtls_happy_path_and_rotation_without_downtime() {
    init_crypto_provider();
    let ca = make_ca();
    let (server_v1, _, _) = make_leaf(&ca, "localhost");
    let (server_v2, _, _) = make_leaf(&ca, "localhost");
    let (client_leaf, _, client_key) = make_leaf(&ca, "client.local");

    let resolver = HotCertResolver::new(Arc::new(server_v1.clone()));
    let server_cfg = server_config(resolver.clone(), root_store(&ca));
    let (addr, shutdown) = start_echo_server(server_cfg).await;

    let connector = TlsConnector::from(client_config(
        &root_store(&ca),
        client_leaf.cert.clone(),
        client_key.clone_key(),
    ));

    // Initial connection works with v1 cert and stays up through rotation.
    let mut tls = connect_stream(&connector, addr)
        .await
        .expect("handshake v1");
    tls.write_all(b"ping-1").await.expect("write ping-1");
    let mut buf1 = [0u8; 6];
    tls.read_exact(&mut buf1).await.expect("read ping-1");
    assert_eq!(&buf1, b"ping-1");

    // Rotate server cert while keeping listener alive.
    resolver.swap(Arc::new(server_v2.clone()));

    // Existing connection keeps working.
    tls.write_all(b"ping-2").await.expect("write ping-2");
    let mut buf2 = [0u8; 6];
    tls.read_exact(&mut buf2).await.expect("read ping-2");
    assert_eq!(&buf2, b"ping-2");

    // New connections see the rotated cert without downtime.
    let echo3 = connect_and_echo(&connector, addr, b"ping-3")
        .await
        .expect("handshake v2");
    assert_eq!(echo3, b"ping-3");

    let _ = shutdown.send(());
}

#[tokio::test]
async fn mtls_rejects_invalid_client_certificate() {
    init_crypto_provider();
    let ca = make_ca();
    let (server_cert, _, _) = make_leaf(&ca, "localhost");
    let (client_cert, _, client_key) = make_leaf(&ca, "client.local");
    let bad_ca = make_ca();
    let (bad_client_cert, _, bad_client_key) = make_leaf(&bad_ca, "bad.local");

    let resolver = HotCertResolver::new(Arc::new(server_cert));
    let server_cfg = server_config(resolver, root_store(&ca));
    let (addr, shutdown) = start_echo_server(server_cfg).await;

    let good_connector = TlsConnector::from(client_config(
        &root_store(&ca),
        client_cert.cert,
        client_key,
    ));
    let bad_connector = TlsConnector::from(client_config(
        &root_store(&ca),
        bad_client_cert.cert,
        bad_client_key,
    ));

    // Good client succeeds.
    connect_and_echo(&good_connector, addr, b"ok")
        .await
        .expect("good client should handshake");

    // Bad client (wrong CA) is rejected.
    let err = tokio::time::timeout(
        Duration::from_secs(2),
        connect_and_echo(&bad_connector, addr, b"nope"),
    )
    .await
    .expect("timeout waiting for handshake")
    .expect_err("handshake should fail");
    let msg = format!("{err:?}").to_lowercase();
    assert!(
        msg.contains("certificate") || msg.contains("invalid") || msg.contains("alert"),
        "unexpected error message: {msg}"
    );

    let _ = shutdown.send(());
}
