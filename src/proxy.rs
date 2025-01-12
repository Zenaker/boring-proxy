use std::sync::Arc;
use hyper::{
    body::Incoming,
    Method, Request, Response,
};
use hyper_util::rt::TokioIo;
use http_body_util::BodyExt;
use bytes::Bytes;
use tokio_rustls::rustls::ServerConfig;
use crate::{
    cert_manager::CertManager,
    session_manager::SessionManager,
    types::{Error, ResponseResult, log, empty, full},
    websocket_handler::{handle_websocket_upgrade, create_websocket_response},
};
use rquest::{Method as RqMethod, Client as RqClient};

pub struct Proxy {
    cert_manager: Arc<CertManager>,
    session_manager: Arc<SessionManager>,
}

impl Proxy {
    pub async fn new() -> Result<Self, Error> {
        log("PROXY", "Creating new proxy instance...");
        
        // Initialize certificate manager
        let cert_manager = Arc::new(CertManager::new()?);
        let session_manager = Arc::new(SessionManager::new());

        log("PROXY", "Initialized proxy instance");

        Ok(Self {
            cert_manager,
            session_manager,
        })
    }

    pub fn create_server_config(&self, host: &str) -> Result<ServerConfig, Error> {
        // Get or create certificate
        let (cert_chain, key) = self.cert_manager.get_or_create_cert(host)?;

        // Create TLS config
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?;

        // Only enable HTTP/1.1 to avoid WebSocket issues with HTTP/2
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(config)
    }

    pub fn get_ca_cert_pem(&self) -> Result<String, Error> {
        self.cert_manager.get_ca_cert_pem()
    }

    pub fn session_manager(&self) -> Arc<SessionManager> {
        Arc::clone(&self.session_manager)
    }

    async fn handle_websocket_request(
        &self,
        req: Request<Incoming>,
        client: RqClient,
        url: String,
    ) -> ResponseResult {
        // First, make a GET request to handle any redirects
        let res = client.get(&url).send().await?;
        let final_url = res.url().to_string();

        if final_url != url {
            log("WS", &format!("Following WebSocket redirect: {} -> {}", url, final_url));
        }

        // Now proceed with WebSocket upgrade using the final URL
        let headers = req.headers().clone();
        let response = create_websocket_response()?;
        let upgrade = hyper::upgrade::on(req);

        // Handle WebSocket connection in background task
        tokio::spawn(async move {
            match upgrade.await {
                Ok(upgraded) => {
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    if let Err(e) = handle_websocket_upgrade(
                        io,
                        client,
                        final_url,
                        headers,
                    ).await {
                        eprintln!("[ERROR] WebSocket handling failed: {}", e);
                    }
                }
                Err(e) => eprintln!("[ERROR] WebSocket upgrade failed: {}", e),
            }
        });

        Ok(response)
    }

    pub async fn handle_request(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> ResponseResult {
        if req.method() == Method::CONNECT {
            // Handle CONNECT for HTTPS
            let host = req.uri().authority()
                .ok_or("No authority in CONNECT request")?
                .host()
                .to_string();

            // Create server config for the domain
            let server_config = Arc::new(self.create_server_config(&host)?);
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

            // Get the upgrade handle before sending response
            let upgrade = hyper::upgrade::on(req);

            // Send 200 response to establish tunnel
            let response = Response::new(empty());

            // Spawn task to handle the upgraded connection
            let self_clone = Arc::clone(&self);
            tokio::spawn(async move {
                match upgrade.await {
                    Ok(upgraded) => {
                        let io = hyper_util::rt::TokioIo::new(upgraded);

                        // Accept TLS connection
                        match acceptor.accept(io).await {
                            Ok(tls_stream) => {
                                let io = hyper_util::rt::TokioIo::new(tls_stream);

                                // Create service for handling HTTPS requests
                                let host_str = host.clone();
                                let service = hyper::service::service_fn(move |mut req| {
                                    let self_clone = Arc::clone(&self_clone);
                                    let host = host_str.clone();
                                    async move {
                                        let result = async {
                                            // Add scheme and authority if missing
                                            if req.uri().scheme().is_none() {
                                                let mut parts = req.uri().clone().into_parts();
                                                parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
                                                if parts.authority.is_none() {
                                                    parts.authority = Some(host.parse().map_err(|e| Box::new(e) as Error)?);
                                                }
                                                *req.uri_mut() = hyper::http::uri::Uri::from_parts(parts)
                                                    .map_err(|e| Box::new(e) as Error)?;
                                            }

                                            // Forward request using rquest
                                            let url = req.uri().to_string();
                                            let method = match *req.method() {
                                                Method::GET => RqMethod::GET,
                                                Method::POST => RqMethod::POST,
                                                Method::PUT => RqMethod::PUT,
                                                Method::DELETE => RqMethod::DELETE,
                                                Method::PATCH => RqMethod::PATCH,
                                                _ => RqMethod::GET,
                                            };

                                            // Get or create session for this host
                                            let client = self_clone.session_manager.get_or_create_session(&host)?;

                                            // Check if this is a valid WebSocket upgrade request
                                            let is_websocket = req.headers().get(hyper::header::UPGRADE)
                                                .and_then(|v| v.to_str().ok())
                                                .map(|s| s.eq_ignore_ascii_case("websocket"))
                                                .unwrap_or(false)
                                                && req.headers().get(hyper::header::CONNECTION)
                                                    .and_then(|v| v.to_str().ok())
                                                    .map(|s| s.to_lowercase().contains("upgrade"))
                                                    .unwrap_or(false)
                                                && req.headers().get("Sec-WebSocket-Key").is_some()
                                                && req.headers().get("Sec-WebSocket-Version").is_some();

                                            if is_websocket {
                                                log("WS", &format!("Valid WebSocket upgrade request for {}", url));
                                                return self_clone.handle_websocket_request(req, client, url).await;
                                            }

                                            // Build request with rquest client
                                            let mut rq = client.request(method, &url);
                                            
                                            // Forward headers except those handled by rquest's profile
                                            for (k, v) in req.headers() {
                                                let key_str = k.as_str().to_lowercase();
                                                // Only skip headers that would interfere with profile impersonation
                                                if k != hyper::header::USER_AGENT && 
                                                   k != hyper::header::ACCEPT && 
                                                   k != hyper::header::ACCEPT_ENCODING && 
                                                   k != hyper::header::ACCEPT_LANGUAGE && 
                                                   k != hyper::header::HOST &&
                                                   !key_str.starts_with("sec-") {
                                                    rq = rq.header(k, v);
                                                }
                                            }

                                            // Forward request method and body
                                            let body = req.into_body().collect().await.map_err(|e| Box::new(e) as Error)?.to_bytes();
                                            if !body.is_empty() {
                                                rq = rq.header(hyper::header::CONTENT_LENGTH, body.len().to_string());
                                                rq = rq.body(body);
                                            }

                                            // Send request with rquest's profile
                                            let res = rq.send().await.map_err(|e| Box::new(e) as Error)?;

                                            // Convert response
                                            let mut builder = Response::builder()
                                                .status(res.status());

                                            // Forward all response headers
                                            for (k, v) in res.headers() {
                                                builder = builder.header(k, v);
                                            }

                                            let body = res.bytes().await.map_err(|e| Box::new(e) as Error)?;
                                            Ok::<_, Error>(builder.body(full(body))
                                                .map_err(|e| Box::new(e) as Error)?)
                                        }.await;

                                        match result {
                                            Ok(res) => Ok::<_, std::convert::Infallible>(res),
                                            Err(e) => {
                                                eprintln!("[ERROR] HTTPS request failed: {}", e);
                                                Ok(Response::builder()
                                                    .status(500)
                                                    .body(full(format!("Error: {}", e)))
                                                    .unwrap())
                                            }
                                        }
                                    }
                                });

                                // Serve connection based on ALPN
                                let tls_stream = io.into_inner();
                                let alpn = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
                                let io = hyper_util::rt::TokioIo::new(tls_stream);

                                let result = if alpn {
                                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                                        .serve_connection(io, service)
                                        .await
                                } else {
                                    hyper::server::conn::http1::Builder::new()
                                        .preserve_header_case(true)
                                        .title_case_headers(true)
                                        .serve_connection(io, service)
                                        .with_upgrades()
                                        .await
                                };

                                if let Err(e) = result {
                                    eprintln!("[ERROR] HTTPS connection failed: {}", e);
                                }
                            }
                            Err(e) => eprintln!("[ERROR] TLS accept failed: {}", e),
                        }
                    }
                    Err(e) => eprintln!("[ERROR] Connection upgrade failed: {}", e),
                }
            });

            Ok(response)
        } else {
            // Handle regular HTTP requests
            let url = req.uri().to_string();
            
            // Extract host from URL
            let host = req.uri().authority()
                .ok_or("No authority in request")?
                .host()
                .to_string();

            // Get or create session for this host
            let client = self.session_manager.get_or_create_session(&host)?;

            let method = match *req.method() {
                Method::GET => RqMethod::GET,
                Method::POST => RqMethod::POST,
                Method::PUT => RqMethod::PUT,
                Method::DELETE => RqMethod::DELETE,
                Method::PATCH => RqMethod::PATCH,
                _ => RqMethod::GET,
            };

            // Build request with rquest client
            let mut rq = client.request(method, &url);
            
            // Forward headers except those handled by rquest's profile
            for (k, v) in req.headers() {
                let key_str = k.as_str().to_lowercase();
                // Only skip headers that would interfere with profile impersonation
                if k != hyper::header::USER_AGENT && 
                   k != hyper::header::ACCEPT && 
                   k != hyper::header::ACCEPT_ENCODING && 
                   k != hyper::header::ACCEPT_LANGUAGE && 
                   k != hyper::header::HOST &&
                   !key_str.starts_with("sec-") {
                    rq = rq.header(k, v);
                }
            }

            // Forward request method and body
            let body = req.into_body().collect().await?.to_bytes();
            if !body.is_empty() {
                rq = rq.header(hyper::header::CONTENT_LENGTH, body.len().to_string());
                rq = rq.body(body);
            }

            // Send request with rquest's profile
            let res = rq.send().await?;

            // Convert response
            let mut builder = Response::builder()
                .status(res.status());

            // Forward all response headers
            for (k, v) in res.headers() {
                builder = builder.header(k, v);
            }

            let body = res.bytes().await?;
            Ok(builder.body(full(body))?)
        }
    }
}
