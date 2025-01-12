use crate::cert_manager::CertManager;
use rquest::{Client as RqClient, Impersonate};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use std::time::Duration;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct TlsHandler {
    cert_manager: Arc<CertManager>,
    rquest_client: RqClient,
}

// Implement Send + Sync for TlsHandler
unsafe impl Send for TlsHandler {}
unsafe impl Sync for TlsHandler {}

impl TlsHandler {
    pub fn new(cert_manager: Arc<CertManager>) -> Result<Self, Error> {
        // Create rquest client with Chrome impersonation for outbound connections
        let rquest_client = RqClient::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .impersonate(Impersonate::Chrome131)
            .build()?;

        Ok(Self {
            cert_manager,
            rquest_client,
        })
    }

    pub async fn handle_inbound_tls(
        &self,
        client_stream: TcpStream,
        host: &str,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, Error> {
        // Get or create certificate for the domain
        let (cert_chain, key) = self.cert_manager.get_or_create_cert(host).await?;

        // Create TLS config for inbound connection
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;
        
        let acceptor = TlsAcceptor::from(Arc::new(config));

        // Accept TLS connection
        Ok(acceptor.accept(client_stream).await?)
    }

    pub async fn handle_connect(
        &self,
        mut client_stream: TcpStream,
        host: &str,
        _port: u16, // Prefix with underscore to indicate intentionally unused
    ) -> Result<(), Error> {
        // Send 200 Connection Established
        client_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

        // Create TLS-wrapped stream for inbound connection
        let mut inbound_tls = self.handle_inbound_tls(client_stream, host).await?;

        // Read the initial request from the inbound TLS stream
        let mut buffer = Vec::with_capacity(8192);
        let mut temp_buffer = [0u8; 8192];
        
        let n = inbound_tls.read(&mut temp_buffer).await?;
        if n == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&temp_buffer[..n]);

        // Parse the decrypted request
        let (method, path) = self.parse_request(&buffer)?;
        
        // Construct full URL for the outbound request
        let full_url = format!("https://{}{}", host, path);
        println!("[TLS] Decrypted request: {} {}", method, full_url);
        
        // Log request headers
        if let Ok(headers_str) = std::str::from_utf8(&buffer[..buffer.iter().position(|&x| x == b'\r').unwrap_or(buffer.len())]) {
            println!("[REQ] First line: {}", headers_str);
        }

        // Forward the request using rquest (which handles TLS fingerprint spoofing)
        let mut req = self.rquest_client.request(
            self.method_to_rquest(&method),
            &full_url
        );

        // Forward request body for POST/PUT
        if method == "POST" || method == "PUT" {
            if let Some(body) = self.get_request_body(&buffer) {
                req = req.body(body);
            }
        }

        // Send the request and handle the response
        match req.send().await {
            Ok(res) => {
                println!("[RES] Status: {} for {}", res.status(), full_url);
                
                // Log important response headers
                println!("[RES] Headers:");
                for (key, value) in res.headers().iter().take(5) { // Limit to first 5 headers
                    if let Ok(v) = value.to_str() {
                        println!("  {}: {}", key, v);
                    }
                }
                if res.headers().len() > 5 {
                    println!("  ... {} more headers", res.headers().len() - 5);
                }
                
                // Write response back through TLS stream
                let status_line = format!("HTTP/1.1 {}\r\n", res.status());
                inbound_tls.write_all(status_line.as_bytes()).await?;

                // Write headers
                for (key, value) in res.headers() {
                    let header_line = format!("{}: {}\r\n", key, value.to_str().unwrap_or(""));
                    inbound_tls.write_all(header_line.as_bytes()).await?;
                }
                inbound_tls.write_all(b"\r\n").await?;

                // Write body
                let body = res.bytes().await?;
                inbound_tls.write_all(&body).await?;
                inbound_tls.flush().await?;
                Ok(())
            },
            Err(e) => {
                eprintln!("[ERROR] Request failed for {}: {}", full_url, e);
                let error_msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}", e);
                inbound_tls.write_all(error_msg.as_bytes()).await?;
                inbound_tls.flush().await?;
                Err(e.into())
            }
        }
    }

    fn parse_request(&self, buffer: &[u8]) -> Result<(String, String), Error> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        
        match req.parse(buffer)? {
            httparse::Status::Complete(_) => {
                let method = req.method.ok_or("No method")?.to_string();
                let path = req.path.ok_or("No path")?.to_string();
                Ok((method, path))
            },
            httparse::Status::Partial => {
                Err("Incomplete request".into())
            }
        }
    }

    fn get_request_body(&self, buffer: &[u8]) -> Option<String> {
        if let Ok(request_str) = std::str::from_utf8(buffer) {
            if let Some(body_start) = request_str.find("\r\n\r\n") {
                return Some(request_str[body_start + 4..].to_string());
            }
        }
        None
    }

    fn method_to_rquest(&self, method: &str) -> rquest::Method {
        match method.to_uppercase().as_str() {
            "GET" => rquest::Method::GET,
            "POST" => rquest::Method::POST,
            "PUT" => rquest::Method::PUT,
            "DELETE" => rquest::Method::DELETE,
            "PATCH" => rquest::Method::PATCH,
            _ => rquest::Method::GET,
        }
    }
}
