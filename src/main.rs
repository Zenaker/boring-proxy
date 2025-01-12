mod cert_manager;
mod session_manager;
mod types;
mod websocket_handler;
mod proxy;

use std::sync::Arc;
use tokio::net::TcpListener;
use hyper::{service::service_fn};
use hyper_util::rt::TokioIo;
use std::time::Duration;
use types::{Error, log, full};
use proxy::Proxy;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let addr = "127.0.0.1:8888";
    log("PROXY", &format!("Starting MITM proxy on http://{}", addr));

    // Initialize proxy
    let proxy = Arc::new(Proxy::new().await?);
    
    // Print CA certificate for installation if needed
    let ca_cert = proxy.get_ca_cert_pem()?;
    log("CERT", "CA Certificate (install this in your browser if not already installed):");
    println!("{}", ca_cert);

    // Start listening
    let listener = TcpListener::bind(addr).await?;
    log("PROXY", &format!("Server listening on {}", addr));
    log("PROXY", "Waiting for connections...");

    // Spawn session cleanup task
    let proxy_clone = Arc::clone(&proxy);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await; // Clean up every 5 minutes
            proxy_clone.session_manager().cleanup_sessions();
        }
    });

    loop {
        let (stream, addr) = listener.accept().await?;
        log("CONN", &format!("New connection from: {}", addr));

        let proxy = Arc::clone(&proxy);

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            let service = service_fn(move |req| {
                let proxy = proxy.clone();
                async move { 
                    match proxy.handle_request(req).await {
                        Ok(res) => Ok::<_, std::convert::Infallible>(res),
                        Err(e) => {
                            eprintln!("[ERROR] Request failed: {}", e);
                            Ok(hyper::Response::builder()
                                .status(500)
                                .body(full(format!("Error: {}", e)))
                                .unwrap())
                        }
                    }
                }
            });

            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                eprintln!("[ERROR] Connection failed: {}", err);
            }
        });
    }
}
