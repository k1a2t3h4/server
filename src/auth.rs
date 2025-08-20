use axum::{
    http::StatusCode,
    response::Json,
    extract::{State, Json as JsonExtractor},
};
use mongodb::bson::Document;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use chrono;
use crate::state::AppState;

// Login request structure
#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub session_type: Option<String>,
    pub session_value: Option<i32>,
}

// Login response structure
#[derive(Serialize)]
pub struct LoginResponse {
    pub message: String,
    pub user: UserData,
    pub session_info: SessionInfo,
    pub token: String,
}

#[derive(Serialize)]
pub struct UserData {
    pub email: String,
    pub websites: Vec<Value>, // changed from Vec<String> to Vec<Value>
}

#[derive(Serialize)]
pub struct SessionInfo {
    pub expires_at: String,
    pub session_type: String,
    pub session_value: Option<i32>,
    pub email: String,
    pub websites: Vec<Value>, // changed from Vec<String> to Vec<Value>
}

// Helper function to get email structure (similar to server.js)
pub fn get_email_structure(email: &str) -> (String, String) {
    let first_char = email.chars().next().unwrap_or('a').to_lowercase().next().unwrap_or('a');
    let second_char = email.chars().nth(1).unwrap_or('a').to_lowercase().next().unwrap_or('a');
    let third_char = email.chars().nth(2).unwrap_or('a').to_lowercase().next().unwrap_or('a');
    
    let db_name = first_char.to_string();
    let collection_name = format!("{}{}", second_char, third_char);
    
    (db_name, collection_name)
}

// Login handler
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    JsonExtractor(login_req): JsonExtractor<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let email = login_req.email;
    let password = login_req.password;
    
    if email.is_empty() || password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    // Get database and collection names from email
    let (db_name, collection_name) = get_email_structure(&email);
    
    // Find user in email-based collection
    let email_db = state.client.database(&db_name);
    let email_collection = email_db.collection::<Document>(&collection_name);
    
    // Create filter for user lookup
    let filter = mongodb::bson::doc! {
        "_id": &email,
        "password": &password
    };
    println!("{:?}", filter);
    
    // Find user
    let user = match email_collection.find_one(filter, None).await {
        Ok(Some(user)) => user,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };
    
    // Get user's websites (full objects)
    let websites_full: Vec<Value> = user
        .get_array("websites")
        .map(|arr| {
            arr.iter()
                .filter_map(|val| {
                    if let Some(doc) = val.as_document() {
                        let complete_unique_id = doc.get_str("complete_unique_id").unwrap_or("").to_string();
                        let subdomain = doc.get_str("subdomain").unwrap_or("").to_string();
                        Some(serde_json::json!({
                            "complete_unique_id": complete_unique_id,
                            "subdomain": subdomain
                        }))
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_else(|_| Vec::new());

    // Generate JWT token
    let session_type = login_req.session_type.as_deref().unwrap_or("day");
    let token = state
        .jwt_manager
        .generate_token(&email, session_type, login_req.session_value, &websites_full)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Calculate session expiration
    let mut expires_at = chrono::Utc::now();
    if let Some(ref stype) = login_req.session_type {
        match stype.as_str() {
            "day" => expires_at += chrono::Duration::days(1),
            "week" => expires_at += chrono::Duration::weeks(1),
            "month" => expires_at += chrono::Duration::days(30),
            "custom" => {
                if let Some(session_value) = login_req.session_value {
                    expires_at += chrono::Duration::hours(session_value as i64);
                }
            }
            _ => {}
        }
    }

    // Build response
    let response = LoginResponse {
        message: "Login successful".to_string(),
        user: UserData {
            email: email.clone(),
            websites: websites_full.clone(),
        },
        session_info: SessionInfo {
            expires_at: expires_at.to_rfc3339(),
            session_type: login_req.session_type.unwrap_or_else(|| "day".to_string()),
            session_value: login_req.session_value,
            email: email.clone(),
            websites: websites_full.clone(),
        },
        token,
    };

    Ok(Json(response))
}
