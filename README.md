# Boring Proxy

A high-performance HTTP/HTTPS/WebSocket proxy server implemented in Rust that provides comprehensive browser fingerprint rotation and intelligent SSL/TLS certificate management. The proxy can accurately mimic TLS fingerprints, headers, and connection behavior from 45+ different browser profiles, making it ideal for applications requiring robust browser fingerprint management.

The proxy maintains perfect profile consistency across all protocols (HTTP, HTTPS, WebSocket) by implementing:
- Profile-specific TLS settings and cipher suites
- Accurate header ordering and formatting
- Protocol-specific behavior patterns
- Connection-level characteristics
- WebSocket handshake patterns

## Features

- **Full MITM Proxy Support**
  - HTTP/1.1 and HTTP/2 support
  - HTTPS tunneling via CONNECT
  - WebSocket protocol support
  - Efficient async I/O operations

- **Advanced Browser Profile Rotation**
  - 45+ browser profiles with perfect TLS fingerprint matching:
    * Chrome (100-131)
    * Safari (15.3-18.2)
    * Safari iOS (16.5-18.1.1)
    * Edge (101-131)
    * Firefox (109-133)
    * OkHttp (3.9-5.0)
  - Profile-specific features:
    * TLS/SSL settings and cipher suites
    * Header ordering and formatting
    * Protocol behavior patterns
    * Connection characteristics
    * Cookie and state management
    * WebSocket handshake consistency

- **Intelligent Certificate Management**
  - Smart certificate detection and reuse
  - Dynamic certificate generation
  - 89-day certificate caching
  - Proper certificate chain handling
  - PEM format storage
  - WebSocket TLS support

- **Performance Optimized**
  - Async I/O for high concurrency
  - Efficient certificate caching
  - Memory-optimized buffer handling
  - Resource cleanup and management
  - Connection pooling
  - Efficient body handling

## Requirements

- Rust toolchain (cargo, rustc)
- Network access for proxy testing
- SSL certificate installation capability
- WebSocket-capable client for testing

## Installation & Setup

1. Clone the repository:
```bash
git clone https://github.com/Zenaker/boring-proxy.git
cd boring-proxy
```

2. Build the project:
```bash
cargo build --release
```

3. Run the proxy:
```bash
cargo run --release
```

The proxy will start on `localhost:8888` by default.

4. Certificate Setup:
- On first run, the proxy will generate a CA certificate
- Find the generated certificates:
  * `ca.crt` - CA certificate
  * `ca.key` - CA private key
- Install the CA certificate (`ca.crt`) in your browser/system

## Usage

1. Configure your browser/client to use the proxy:
   - Proxy Address: `localhost`
   - Port: `8888`

2. Install the CA certificate in your browser/system trust store

3. Start making requests - the proxy will automatically:
   - Rotate browser profiles
   - Handle HTTP/HTTPS/WebSocket traffic
   - Manage certificates
   - Log operations

## Development

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release
```

### Testing

1. Manual Testing Tools:
   - curl for HTTP testing
   - wscat for WebSocket testing
   - Browser dev tools for inspection
   - OpenSSL for certificate verification

2. Profile Testing:
   - Browser fingerprint verification
   - TLS handshake inspection
   - Header consistency checks
   - WebSocket protocol testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

[Add contribution guidelines here]
