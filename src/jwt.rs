use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde_json::Value;
// JWT Secret (in production, use environment variable)
const JWT_SECRET: &str = "your-secret-key-change-in-production";

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // Subject (user email)
    pub email: String,
    pub exp: i64, // Expiration time
    pub iat: i64, // Issued at
    pub jti: String, // JWT ID (unique identifier)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub user_email: String,
    pub email: String,
    pub websites: Vec<Value>,
    pub session_type: String,
    pub session_value: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// In-memory session store (in production, use Redis or database)
pub type SessionStore = Arc<RwLock<HashMap<String, SessionData>>>;

pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    sessions: SessionStore,
}

impl JwtManager {
    pub fn new() -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(JWT_SECRET.as_ref()),
            decoding_key: DecodingKey::from_secret(JWT_SECRET.as_ref()),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn generate_token(&self, email: &str, session_type: &str, session_value: Option<i32>, websites: &[Value]) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let expires_at = match session_type {
            "day" => now + chrono::Duration::days(1),
            "week" => now + chrono::Duration::weeks(1),
            "month" => now + chrono::Duration::days(30),
            "custom" => {
                if let Some(hours) = session_value {
                    now + chrono::Duration::hours(hours as i64)
                } else {
                    now + chrono::Duration::days(1) // Default to 1 day
                }
            },
            _ => now + chrono::Duration::days(1), // Default to 1 day
        };

        let claims = Claims {
            sub: email.to_string(), // Use email as subject
            email: email.to_string(),
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)?;

        // Store session data
        let session_data = SessionData {
            user_email: email.to_string(),
            email: email.to_string(),
            websites: websites.to_vec(),
            session_type: session_type.to_string(),
            session_value,
            created_at: now,
            expires_at,
        };

        // Store in memory (in production, use Redis or database)
        let sessions = self.sessions.clone();
        let jti = claims.jti.clone();
        tokio::spawn(async move {
            let mut sessions = sessions.write().await;
            sessions.insert(jti, session_data);
        });

        Ok(token)
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &Validation::default())?;
        
        // Check if session exists in store and cleanup if expired
        let sessions = self.sessions.clone();
        let jti = token_data.claims.jti.clone();
        tokio::spawn(async move {
            let mut sessions = sessions.write().await;
            if let Some(session) = sessions.get(&jti) {
                if Utc::now() > session.expires_at {
                    sessions.remove(&jti);
                }
            }
        });

        Ok(token_data.claims)
    }

    pub async fn get_session(&self, jti: &str) -> Option<SessionData> {
        let sessions = self.sessions.read().await;
        sessions.get(jti).cloned()
    }

    pub async fn invalidate_session(&self, jti: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(jti);
    }

    // pub async fn cleanup_expired_sessions(&self) {
    //     let mut sessions = self.sessions.write().await;
    //     let now = Utc::now();
    //     sessions.retain(|_, session| session.expires_at > now);
    // }
}

impl Default for JwtManager {
    fn default() -> Self {
        Self::new()
    }
} 