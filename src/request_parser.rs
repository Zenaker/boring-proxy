use std::collections::HashMap;
type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub is_websocket: bool,
}

impl Request {
    pub fn is_upgrade_request(&self) -> bool {
        self.headers.get("Upgrade")
            .map(|v| v.to_lowercase() == "websocket")
            .unwrap_or(false)
            && self.headers.get("Connection")
                .map(|v| v.to_lowercase().contains("upgrade"))
                .unwrap_or(false)
    }
}

pub fn parse_request(buffer: &[u8]) -> Result<Request, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    
    match req.parse(buffer)? {
        httparse::Status::Complete(_) => {
            let method = req.method.ok_or("No method")?.to_string();
            let path = req.path.ok_or("No path")?.to_string();
            
            // Parse headers into HashMap
            let mut header_map = HashMap::new();
            for header in req.headers.iter() {
                if let Ok(value) = std::str::from_utf8(header.value) {
                    header_map.insert(header.name.to_string(), value.to_string());
                }
            }
            
            let body = get_request_body(buffer);
            let is_websocket = header_map.get("Upgrade")
                .map(|v| v.to_lowercase() == "websocket")
                .unwrap_or(false);
            
            Ok(Request {
                method,
                path,
                headers: header_map,
                body,
                is_websocket,
            })
        },
        httparse::Status::Partial => {
            Err("Incomplete request".into())
        }
    }
}

fn get_request_body(buffer: &[u8]) -> Option<String> {
    if let Ok(request_str) = std::str::from_utf8(buffer) {
        if let Some(body_start) = request_str.find("\r\n\r\n") {
            return Some(request_str[body_start + 4..].to_string());
        }
    }
    None
}
