use rquest::{Client as RqClient, Method as RqMethod, Message, cookie::Jar};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use futures_util::{SinkExt, StreamExt};
use crate::request_parser::Request;
use crate::session_manager::SessionManager;
use std::sync::Arc;
use url::Url;

type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct HttpHandler {
    session_manager: Arc<SessionManager>,
}

#[derive(Debug)]
struct WebSocketContext {
    key: String,
    version: String,
    protocols: Vec<String>,
}

impl WebSocketContext {
    fn from_headers(headers: &std::collections::HashMap<String, String>) -> Option<Self> {
        let key = headers.get("Sec-WebSocket-Key")?.to_string();
        let version = headers.get("Sec-WebSocket-Version")?.to_string();
        let protocols = headers
            .get("Sec-WebSocket-Protocol")
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(Vec::new);
        
        Some(WebSocketContext {
            key,
            version,
            protocols,
        })
    }
}

// Implement Send + Sync for HttpHandler
unsafe impl Send for HttpHandler {}
unsafe impl Sync for HttpHandler {}

impl HttpHandler {
    pub fn new(session_manager: Arc<SessionManager>) -> Self {
        Self { 
            session_manager,
        }
    }

    pub async fn handle_request(
        &self,
        mut client_stream: TcpStream,
        request: Request,
    ) -> Result<(), Error> {
        // Handle WebSocket upgrade if needed
        if request.is_websocket {
            return self.handle_websocket(client_stream, request).await;
        }

        // Construct full URL if needed
        let full_url = if request.path.starts_with("http://") {
            request.path.clone()
        } else {
            format!("http://{}", request.path)
        };
        println!("[HTTP] Forwarding request: {} {}", request.method, full_url);

        // Extract host from URL
        let url = Url::parse(&full_url)?;
        let host = url.host_str().ok_or("Invalid host")?;
        
        // Get client for this host with rotated profile
        let client = self.session_manager.get_or_create_session(host)?;
        
        // Create request with client
        let mut req = client.request(
            self.method_to_rquest(&request.method),
            &full_url
        );

        // Add headers
        for (key, value) in request.headers.iter() {
            let key_lower = key.to_lowercase();
            // Skip hop-by-hop headers and headers that should be handled by the profile
            if !Self::is_hop_by_hop_header(&key_lower) 
               && !key_lower.starts_with("sec-")
               && !key_lower.contains("user-agent")
               && !key_lower.contains("accept")
               && key_lower != "host" {
                req = req.header(key, value);
            }
        }

        // Add body if present
        if let Some(body) = request.body {
            if request.method == "POST" || request.method == "PUT" {
                req = req.body(body);
            }
        }

        // Send request and handle response
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
                
                // Write status line
                let status_line = format!("HTTP/1.1 {}\r\n", res.status());
                client_stream.write_all(status_line.as_bytes()).await?;

                // Write headers
                for (key, value) in res.headers() {
                    let header_line = format!("{}: {}\r\n", key, value.to_str().unwrap_or(""));
                    client_stream.write_all(header_line.as_bytes()).await?;
                }
                client_stream.write_all(b"\r\n").await?;

                // Write body
                let body = res.bytes().await?;
                client_stream.write_all(&body).await?;
                client_stream.shutdown().await?;
                Ok(())
            },
            Err(e) => {
                eprintln!("[ERROR] Request failed for {}: {}", full_url, e);
                let error_msg = format!("HTTP/1.1 502 Bad Gateway\r\n\r\n{}", e);
                client_stream.write_all(error_msg.as_bytes()).await?;
                client_stream.shutdown().await?;
                Err(e.into())
            }
        }
    }

    async fn handle_websocket(&self, mut client_stream: TcpStream, request: Request) -> Result<(), Error> {
        println!("[WS] WebSocket upgrade request for {}", request.path);

        let ws_ctx = WebSocketContext::from_headers(&request.headers)
            .ok_or("Invalid WebSocket headers")?;

        // Extract host from URL
        let ws_url = if request.path.starts_with("ws://") {
            request.path.clone()
        } else {
            format!("ws://{}", request.path)
        };
        let url = Url::parse(&ws_url)?;
        let host = url.host_str().ok_or("Invalid host")?;
        
        // Get client for this host with rotated profile
        let client = self.session_manager.get_or_create_session(host)?;

        // Forward WebSocket connection
        let websocket = client
            .websocket(&ws_url)
            .key(&ws_ctx.key)
            .protocols(ws_ctx.protocols.iter().map(String::as_str).collect::<Vec<_>>())
            .send()
            .await?
            .into_websocket()
            .await?;

        let (mut ws_write, mut ws_read) = websocket.split();
        let (mut client_read, mut client_write) = client_stream.split();

        // Client to server
        let client_to_server = async move {
            let mut buffer = vec![0; 8192];
            loop {
                match client_read.read(&mut buffer).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        if let Ok(msg) = Message::binary(&buffer[..n]) {
                            if ws_write.send(msg).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        };

        // Server to client
        let server_to_client = async move {
            while let Some(msg) = ws_read.next().await {
                match msg {
                    Ok(msg) => {
                        let data = match msg {
                            Message::Binary(data) => data,
                            Message::Text(text) => text.into_bytes(),
                            _ => continue,
                        };
                        if client_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        };

        // Run both directions concurrently
        tokio::select! {
            _ = client_to_server => {},
            _ = server_to_client => {},
        }

        Ok(())
    }

    fn is_hop_by_hop_header(header: &str) -> bool {
        let header = header.to_lowercase();
        matches!(
            header.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
        )
    }

    fn method_to_rquest(&self, method: &str) -> RqMethod {
        match method.to_uppercase().as_str() {
            "GET" => RqMethod::GET,
            "POST" => RqMethod::POST,
            "PUT" => RqMethod::PUT,
            "DELETE" => RqMethod::DELETE,
            "PATCH" => RqMethod::PATCH,
            _ => RqMethod::GET,
        }
    }
}
