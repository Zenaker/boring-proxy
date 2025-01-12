use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use rquest::{Client as RqClient, Impersonate, cookie::Jar};
use crate::types::{Error, PROFILES, log};
use rand::seq::SliceRandom;
use rand::thread_rng;

#[derive(Clone)]
pub struct Session {
    pub client: RqClient,
    pub profile: Impersonate,
    pub last_used: Instant,
    pub cookie_jar: Arc<Jar>,
}

pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn create_client(profile: Impersonate, cookie_jar: Arc<Jar>) -> Result<RqClient, Error> {
        // Create builder with impersonation
        let mut builder = RqClient::builder()
            .impersonate(profile)
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .cookie_provider(cookie_jar)
            .no_proxy(); // Ensure we don't use system proxy
        
        // Build the client
        let client = builder.build()?;
        
        // Log the profile being used
        log("SESSION", &format!("Created client with profile: {:?}", profile));
        
        Ok(client)
    }

    pub fn get_or_create_session(&self, host: &str) -> Result<RqClient, Error> {
        let mut sessions = self.sessions.lock();
        
        // Randomly select a profile for this request
        let new_profile = *PROFILES.choose(&mut thread_rng()).expect("PROFILES array cannot be empty");
        
        if let Some(session) = sessions.get_mut(host) {
            log("SESSION", &format!(
                "Rotating profile for host: {} from {:?} to {:?}",
                host, session.profile, new_profile
            ));
            
            session.last_used = Instant::now();
            
            // Log profile change
            log("SESSION", &format!(
                "Using profile: {:?} for request to {}", new_profile, host
            ));
            
            // Create new client with rotated profile but reuse cookie jar
            let new_client = Self::create_client(new_profile, Arc::clone(&session.cookie_jar))?;
            
            // Update session
            session.client = new_client;
            session.profile = new_profile;
            
            Ok(session.client.clone())
        } else {
            log("SESSION", &format!("Creating new session for host: {} with profile: {:?}", host, new_profile));
            
            // Create shared cookie jar for the session
            let cookie_jar = Arc::new(Jar::default());
            
            // Log new profile
            log("SESSION", &format!(
                "Using profile: {:?} for new session to {}", new_profile, host
            ));
            
            // Create client with profile
            let client = Self::create_client(new_profile, Arc::clone(&cookie_jar))?;
            let client_clone = client.clone();

            sessions.insert(host.to_string(), Session {
                client,
                profile: new_profile,
                last_used: Instant::now(),
                cookie_jar,
            });
            
            Ok(client_clone)
        }
    }

    pub fn cleanup_sessions(&self) {
        let mut sessions = self.sessions.lock();
        let now = Instant::now();
        sessions.retain(|host, session| {
            let keep = now.duration_since(session.last_used) < Duration::from_secs(1800); // 30 minute timeout
            if !keep {
                log("SESSION", &format!("Cleaning up inactive session for host: {}", host));
            }
            keep
        });
    }

    pub fn sessions(&self) -> Arc<Mutex<HashMap<String, Session>>> {
        Arc::clone(&self.sessions)
    }
}
