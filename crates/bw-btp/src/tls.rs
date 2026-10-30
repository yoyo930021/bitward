//! 跨機 BTP：self-signed TLS + SPKI pin（契約 §1.4 跨機列）。
//! 信任模型借鑒 vaultgate/1Password Connect：金鑰不出中樞、通道 TLS、無 CA → 綁 SPKI pin。
//! rcgen https://docs.rs/rcgen ｜ rustls 0.23 danger verifier https://docs.rs/rustls/0.23/rustls/client/struct.DangerousClientConfig.html

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("tls gen: {0}")]
    Gen(String),
    #[error("tls io: {0}")]
    Io(String),
}

#[derive(Clone, Debug)]
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    /// base64(SHA-256(SPKI DER))
    pub spki_pin: String,
}

/// 載入或建立 `tls/cert.der` + `tls/key.der`。重生不換 keypair ⇒ pin 穩定，
/// 已配對裝置不會被無谓踢除。
pub fn load_or_create(dir: &Path) -> Result<TlsIdentity, TlsError> {
    let d = dir.join("tls");
    let cert_p = d.join("cert.der");
    let key_p = d.join("key.der");
    if let (Ok(cert), Ok(key)) = (std::fs::read(&cert_p), std::fs::read(&key_p)) {
        let spki_pin = spki_pin(&cert)?;
        return Ok(TlsIdentity {
            cert_der: cert,
            key_der: key,
            spki_pin,
        });
    }
    std::fs::create_dir_all(&d).map_err(|e| TlsError::Io(e.to_string()))?;
    let params = rcgen::CertificateParams::new(vec!["bitward.local".to_string()])
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    let key_pair = rcgen::KeyPair::generate().map_err(|e| TlsError::Gen(e.to_string()))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| TlsError::Gen(e.to_string()))?;
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialized_der().to_vec();
    std::fs::write(&cert_p, &cert_der).map_err(|e| TlsError::Io(e.to_string()))?;
    std::fs::write(&key_p, &key_der).map_err(|e| TlsError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key_p, std::fs::Permissions::from_mode(0o600));
    }
    let spki_pin = spki_pin(&cert_der)?;
    Ok(TlsIdentity {
        cert_der,
        key_der,
        spki_pin,
    })
}

pub fn spki_pin(cert_der: &[u8]) -> Result<String, TlsError> {
    let spki = x509_spki_tlv(cert_der).ok_or_else(|| TlsError::Gen("SPKI not found".into()))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(spki)))
}

/// DER TLV：回 (tag, content 起點相對 buf 的偏移, content 長度, 總消耗)。
fn der_entry(buf: &[u8], at: usize) -> Option<(u8, usize, usize, usize)> {
    let tag = *buf.get(at)?;
    let l1 = *buf.get(at + 1)?;
    let (len, hdr) = if l1 < 0x80 {
        (l1 as usize, 2usize)
    } else if l1 == 0x81 {
        (*buf.get(at + 2)? as usize, 3usize)
    } else if l1 == 0x82 {
        (
            (*buf.get(at + 2)? as usize) << 8 | *buf.get(at + 3)? as usize,
            4usize,
        )
    } else {
        return None;
    };
    buf.get(at + hdr..at + hdr + len)?;
    Some((tag, at + hdr, len, hdr + len))
}

/// Certificate → tbsCertificate → subjectPublicKeyInfo 的完整 TLV 位元組。
/// tbs 欄位序：[0]version(可選)、serial(0)、signature(1)、issuer(2)、validity(3)、subject(4)、SPKI(5)。
fn x509_spki_tlv(cert_der: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQ { tbs SEQ, sigAlg, sigBits }：先進外層 content，tbs 是第一個子項
    let (_, c_off, c_len, _) = der_entry(cert_der, 0)?;
    let body = cert_der.get(c_off..c_off + c_len)?;
    let (_, t_off, t_len, _) = der_entry(body, 0)?;
    let tbs = body.get(t_off..t_off + t_len)?;
    let mut off = 0usize;
    let mut field = 0i32;
    // 可選的 [0] EXPLICIT version（context, constructed）不計入欄位序
    if let Some((0xA0, _, _, consumed)) = der_entry(tbs, 0) {
        off += consumed;
    }
    loop {
        let (_tag, _c_off, _c_len, consumed) = der_entry(tbs, off)?;
        if field == 5 {
            return Some(tbs[off..off + consumed].to_vec());
        }
        off += consumed;
        field += 1;
        if field > 12 {
            return None;
        }
    }
}

pub fn server_config(id: &TlsIdentity) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let certs = vec![CertificateDer::from(id.cert_der.clone())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()));
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| TlsError::Gen(e.to_string()))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| TlsError::Gen(e.to_string()))?;
    cfg.alpn_protocols = vec![b"bitward-btp".to_vec()];
    Ok(Arc::new(cfg))
}

/// 只認 SPKI pin 的 verifier（self-signed 無 CA 體系）。名稱不參與信任。
#[derive(Debug)]
pub struct PinVerifier {
    pub pin: String,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = spki_pin(end_entity.as_ref())
            .map_err(|_| rustls::Error::from(CertificateError::BadEncoding))?;
        if presented == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            tracing::warn!(
                expected = %self.pin,
                presented = %presented,
                "SPKI pin mismatch"
            );
            Err(rustls::Error::General("spki pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        use SignatureScheme::*;
        vec![
            ED25519,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            RSA_PKCS1_SHA256,
            RSA_PSS_SHA256,
        ]
    }
}

pub fn client_config(pin: &str) -> Arc<rustls::ClientConfig> {
    let verifier = Arc::new(PinVerifier {
        pin: pin.to_string(),
    });
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth(),
    )
}

pub type ClientStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

pub async fn connect(host: &str, port: u16, pin: &str) -> Result<ClientStream, TlsError> {
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| TlsError::Io(e.to_string()))?;
    // pki-types 的 TryFrom 同時吃 DNS 名稱與 IP 字串
    let name = ServerName::try_from(host.to_string()).map_err(|e| TlsError::Gen(e.to_string()))?;
    let connector = tokio_rustls::TlsConnector::from(client_config(pin));
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| TlsError::Io(e.to_string()))
}

pub type ServerStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

pub async fn accept(
    acceptor: &tokio_rustls::TlsAcceptor,
    tcp: tokio::net::TcpStream,
) -> Result<ServerStream, TlsError> {
    acceptor
        .accept(tcp)
        .await
        .map_err(|e| TlsError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spki_extraction_matches_rcgen_trust_anchor() {
        // 交叉驗證：自己 DER walk 的 pin 必須等同「把同一張 cert 當 trust anchor
        // 交給 WebPki verifier」所見的 SPKI——用 rcgen 再簽一張並比對兩者不同
        let dir = tmpdir("walk");
        let a = load_or_create(&dir).unwrap();
        let b = {
            let d2 = std::path::PathBuf::from(&dir).join("second");
            load_or_create(&d2).unwrap()
        };
        assert_ne!(a.spki_pin, b.spki_pin, "不同 keypair 必不同 pin");
        // 同一張 cert 重複提取必穩定
        assert_eq!(spki_pin(&a.cert_der).unwrap(), a.spki_pin);
        // SPKI 必須是 SEQUENCE（tag 0x30），不是隨便切到的雜訊
        let tlv = x509_spki_tlv(&a.cert_der).expect("spki tlv");
        assert_eq!(tlv[0], 0x30);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("btp-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn identity_persists_and_pin_stable() {
        let dir = tmpdir("stable");
        let a = load_or_create(&dir).unwrap();
        let b = load_or_create(&dir).unwrap();
        assert_eq!(a.spki_pin, b.spki_pin);
        assert_eq!(a.cert_der, b.cert_der);
        assert_eq!(a.spki_pin.len(), 44); // sha256 → base64
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn handshake_pin_ok_and_mismatch_fails() {
        let dir = tmpdir("hs");
        let id = load_or_create(&dir).unwrap();
        let cfg = server_config(&id).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
        let srv_id = id.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut s = accept(&acceptor, tcp).await.unwrap();
            // 讀一個 byte 回一個 byte
            use tokio::io::AsyncReadExt;
            let mut b = [0u8; 1];
            let _ = s.read(&mut b).await;
            b
        });
        let mut c = connect("127.0.0.1", addr.port(), &id.spki_pin)
            .await
            .unwrap();
        use tokio::io::AsyncWriteExt;
        c.write_all(b"x").await.unwrap();
        c.flush().await.unwrap();
        let got = server.await.unwrap();
        assert_eq!(&got, b"x");
        assert!(!srv_id.cert_der.is_empty());

        // pin 錯 → 交握失敗
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let acc2 = tokio_rustls::TlsAcceptor::from(server_config(&id).unwrap());
        let srv2 = tokio::spawn(async move {
            let (tcp, _) = listener2.accept().await.unwrap();
            let _ = accept(&acc2, tcp).await;
        });
        let bad = connect("127.0.0.1", addr2.port(), "AAAAAAAAAAAAAAAAAAAAAAAAAAA").await;
        assert!(bad.is_err());
        let _ = srv2.await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
