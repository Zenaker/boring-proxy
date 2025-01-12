use crate::types::{Error, ResponseResult, empty};
use futures_util::{SinkExt, StreamExt};
use hyper::Response;
use tokio_tungstenite::{tungstenite::protocol::Role, WebSocketStream};
use rquest::{Client as RqClient, Message as RqMessage, CloseCode as RqCloseCode};
use tokio_tungstenite::tungstenite::Message;
use tokio::io::{AsyncRead, AsyncWrite};

pub async fn handle_websocket_upgrade<S>(
    upgraded: S,
    ws_client: RqClient,
    url: String,
    headers: hyper::HeaderMap,
) -> Result<(), Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Create server WebSocket stream
    let server_stream = WebSocketStream::from_raw_socket(
        upgraded,
        Role::Server,
        None
    ).await;

    // Build WebSocket request with rquest client
    let mut ws_req = ws_client.websocket(&url);
    
    // Forward headers except those handled by rquest's profile
    for (k, v) in headers.iter() {
        let key_str = k.as_str().to_lowercase();
        // Only skip headers that would interfere with profile impersonation
        if (k != hyper::header::USER_AGENT && 
            k != hyper::header::ACCEPT && 
            k != hyper::header::ACCEPT_ENCODING && 
            k != hyper::header::ACCEPT_LANGUAGE &&
            k != hyper::header::HOST) ||
           // But keep WebSocket-specific headers
           key_str == "sec-websocket-key" ||
           key_str == "sec-websocket-version" ||
           key_str == "sec-websocket-protocol" {
            ws_req = ws_req.header(k, v);
        }
    }

    // Send request and convert to websocket
    let ws_server = ws_req.send().await?.into_websocket().await?;

    // Split streams for bidirectional communication
    let (server_write, server_read) = server_stream.split();
    let (client_write, client_read) = ws_server.split();

    // Forward client -> server
    let client_to_server = async {
        let mut client_read = client_read;
        let mut server_write = server_write;
        while let Some(msg) = client_read.next().await {
            if let Ok(msg) = msg {
                // Convert rquest::Message to tungstenite::Message
                let msg = match msg {
                    RqMessage::Text(text) => Message::Text(text),
                    RqMessage::Binary(data) => Message::Binary(data),
                    RqMessage::Ping(data) => Message::Ping(data),
                    RqMessage::Pong(data) => Message::Pong(data),
                    RqMessage::Close { code, reason } => {
                        let close_code = match code {
                            RqCloseCode::Normal => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                            RqCloseCode::Away => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away,
                            RqCloseCode::Protocol => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Protocol,
                            RqCloseCode::Unsupported => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported,
                            RqCloseCode::Status => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Status,
                            RqCloseCode::Abnormal => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Abnormal,
                            RqCloseCode::Invalid => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Invalid,
                            RqCloseCode::Policy => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                            RqCloseCode::Size => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                            RqCloseCode::Extension => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Extension,
                            RqCloseCode::Error => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Error,
                            RqCloseCode::Restart => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Restart,
                            RqCloseCode::Again => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Again,
                            _ => tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
                        };
                        Message::Close(Some(
                            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: close_code,
                                reason: reason.unwrap_or_default().into(),
                            }
                        ))
                    }
                };

                if let Err(e) = server_write.send(msg).await {
                    eprintln!("[ERROR] WebSocket send failed: {}", e);
                    break;
                }
            }
        }
    };

    // Forward server -> client
    let server_to_client = async {
        let mut server_read = server_read;
        let mut client_write = client_write;
        while let Some(msg) = server_read.next().await {
            if let Ok(msg) = msg {
                // Convert tungstenite::Message to rquest::Message
                let msg = match msg {
                    Message::Text(text) => RqMessage::Text(text),
                    Message::Binary(data) => RqMessage::Binary(data),
                    Message::Ping(data) => RqMessage::Ping(data),
                    Message::Pong(data) => RqMessage::Pong(data),
                    Message::Close(frame) => {
                        let (code, reason) = frame.map(|f| {
                            let code = match f.code {
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal => RqCloseCode::Normal,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Away => RqCloseCode::Away,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Protocol => RqCloseCode::Protocol,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Unsupported => RqCloseCode::Unsupported,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Status => RqCloseCode::Status,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Abnormal => RqCloseCode::Abnormal,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Invalid => RqCloseCode::Invalid,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy => RqCloseCode::Policy,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size => RqCloseCode::Size,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Extension => RqCloseCode::Extension,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Error => RqCloseCode::Error,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Restart => RqCloseCode::Restart,
                                tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Again => RqCloseCode::Again,
                                _ => RqCloseCode::Normal,
                            };
                            (code, Some(f.reason.to_string()))
                        }).unwrap_or((RqCloseCode::Normal, None));
                        RqMessage::Close { code, reason }
                    }
                    _ => continue,
                };

                if let Err(e) = client_write.send(msg).await {
                    eprintln!("[ERROR] WebSocket send failed: {}", e);
                    break;
                }
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

pub fn create_websocket_response() -> ResponseResult {
    Ok(Response::builder()
        .status(101)
        .header(hyper::header::CONNECTION, "upgrade")
        .header(hyper::header::UPGRADE, "websocket")
        .body(empty())?)
}
