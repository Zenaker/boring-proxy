use boring2::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, ExtendedKeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509,
    },
};
use rustls::{Certificate as RustlsCert, PrivateKey};
use std::{fs, path::Path, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};
use moka::sync::Cache;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

fn log(component: &str, message: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis();
    println!("[{}][{}] {}", timestamp, component, message);
}

pub struct CertManager {
    root_cert: Arc<X509>,
    root_key: Arc<PKey<Private>>,
    cert_cache: Cache<String, (Vec<RustlsCert>, PrivateKey)>,
}

impl CertManager {
    pub fn new() -> Result<Self, Error> {
        log("CERT", "Creating new certificate manager...");
        
        // Check for existing CA certificate and key
        let ca_key_path = Path::new("ca.key");
        let ca_cert_path = Path::new("ca.crt");
        
        let (root_cert, root_key) = if ca_key_path.exists() && ca_cert_path.exists() {
            log("CERT", "Found existing CA certificate and key");
            
            // Load existing CA certificate and key
            let cert_pem = fs::read(ca_cert_path)?;
            let key_pem = fs::read(ca_key_path)?;
            
            let cert = X509::from_pem(&cert_pem)?;
            let key = PKey::private_key_from_pem(&key_pem)?;
            
            log("CERT", "Successfully loaded existing CA certificate and key");
            (cert, key)
        } else {
            log("CERT", "No existing CA certificate found, creating new one");
            Self::create_root_ca()?
        };
        
        log("CERT", "Certificate manager initialized successfully");
        
        Ok(Self {
            root_cert: Arc::new(root_cert),
            root_key: Arc::new(root_key),
            cert_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60 * 60 * 24 * 89)) // 89 days
                .max_capacity(8096)
                .build(),
        })
    }

    fn create_root_ca() -> Result<(X509, PKey<Private>), Error> {
        log("CERT", "Generating new CA certificate");
        
        // Generate RSA key pair
        let rsa = Rsa::generate(4096)?;
        let privkey = PKey::from_rsa(rsa)?;

        // Create CA certificate
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Boring Proxy")?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, "<BORING-PROXY CA>")?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        
        // Generate random serial number
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        let serial_asn1 = serial.to_asn1_integer()?;
        builder.set_serial_number(&serial_asn1)?;

        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?; // self-signed
        builder.set_pubkey(&privkey)?;

        // Set validity period
        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(90)?;
        builder.set_not_after(&not_after)?;

        // Add extensions
        builder.append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()?,
        )?;

        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;

        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))?;
        builder.append_extension(subject_key_id)?;

        // Sign the certificate
        builder.sign(&privkey, MessageDigest::sha256())?;
        let cert = builder.build();

        // Save CA certificate and private key
        let ca_cert_path = Path::new("ca.crt");
        let ca_key_path = Path::new("ca.key");
        log("CERT", "Saving new CA certificate and key");
        fs::write(ca_cert_path, cert.to_pem()?)?;
        fs::write(ca_key_path, privkey.private_key_to_pem_pkcs8()?)?;

        Ok((cert, privkey))
    }

    pub fn get_ca_cert_pem(&self) -> Result<String, Error> {
        Ok(String::from_utf8(self.root_cert.to_pem()?)?)
    }

    pub fn get_or_create_cert(&self, domain: &str) -> Result<(Vec<RustlsCert>, PrivateKey), Error> {
        // Check cache first
        if let Some(cert) = self.cert_cache.get(domain) {
            log("CERT", &format!("Using cached certificate for {}", domain));
            return Ok(cert);
        }

        log("CERT", &format!("Generating new certificate for {}", domain));

        // Generate RSA key pair
        let rsa = Rsa::generate(4096)?;
        let privkey = PKey::from_rsa(rsa)?;

        // Create leaf certificate
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "Boring Proxy")?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, domain)?;
        let name = name_builder.build();

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        
        // Generate random serial number
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        let serial_asn1 = serial.to_asn1_integer()?;
        builder.set_serial_number(&serial_asn1)?;

        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.root_cert.subject_name())?;
        builder.set_pubkey(&privkey)?;

        // Set validity period
        let not_before = Asn1Time::days_from_now(0)?;
        builder.set_not_before(&not_before)?;
        let not_after = Asn1Time::days_from_now(90)?;
        builder.set_not_after(&not_after)?;

        // Add extensions
        builder.append_extension(
            BasicConstraints::new()
                .build()?,
        )?;

        builder.append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;

        let subject_key_id = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(&self.root_cert), None))?;
        builder.append_extension(subject_key_id)?;

        let auth_key_id = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(&self.root_cert), None))?;
        builder.append_extension(auth_key_id)?;

        // Add subject alternative names
        let mut san = SubjectAlternativeName::new();
        san.dns(domain);
        san.dns(&format!("*.{}", domain));
        let san = san.build(&builder.x509v3_context(Some(&self.root_cert), None))?;
        builder.append_extension(san)?;

        // Add extended key usage
        let mut extended_key_usage = ExtendedKeyUsage::new();
        extended_key_usage.server_auth();
        extended_key_usage.client_auth();
        let extended_key_usage = extended_key_usage.build()?;
        builder.append_extension(extended_key_usage)?;

        // Sign with CA key
        builder.sign(&self.root_key, MessageDigest::sha256())?;
        let cert = builder.build();

        // Create certificate chain
        let cert_chain = vec![
            RustlsCert(cert.to_der()?),
            RustlsCert(self.root_cert.to_der()?),
        ];
        let key = PrivateKey(privkey.private_key_to_der()?);

        // Cache the certificate
        log("CERT", &format!("Caching certificate for {}", domain));
        self.cert_cache.insert(domain.to_string(), (cert_chain.clone(), key.clone()));

        Ok((cert_chain, key))
    }
}
