use axum::{
    http::StatusCode,
    response::Json,
    extract::{State, Json as JsonExtractor},
};
use mongodb::bson::{Document, DateTime as BsonDateTime};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::state::AppState;

// Registration request structure
#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

// Registration response structure
#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<RegisterData>,
}

#[derive(Serialize)]
pub struct RegisterData {
    pub email: String,
    pub email_db: String,
    pub email_collection: String,
}

// Helper function to get email structure (same as auth.rs)
pub fn get_email_structure(email: &str) -> (String, String) {
    let first_char = email.chars().next().unwrap_or('a').to_lowercase().next().unwrap_or('a');
    let second_char = email.chars().nth(1).unwrap_or('a').to_lowercase().next().unwrap_or('a');
    let third_char = email.chars().nth(2).unwrap_or('a').to_lowercase().next().unwrap_or('a');
    
    let db_name = first_char.to_string();
    let collection_name = format!("{}{}", second_char, third_char);
    
    (db_name, collection_name)
}

// Registration handler
pub async fn register_handler(
    State(state): State<Arc<AppState>>,
    JsonExtractor(register_req): JsonExtractor<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let email = register_req.email;
    let password = register_req.password;
    
    if email.is_empty() || password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    
    // Get database and collection names from email
    let (email_db_name, email_collection_name) = get_email_structure(&email);
    
    println!("Email structure: db={}, collection={}", email_db_name, email_collection_name);
    
    // Check if user already exists in email-based collection
    let email_db = state.client.database(&email_db_name);
    let email_collection = email_db.collection::<Document>(&email_collection_name);
    
    let existing_user_filter = mongodb::bson::doc! { "_id": &email };
    let existing_user = email_collection.find_one(existing_user_filter, None).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    if existing_user.is_some() {
        return Ok(Json(RegisterResponse {
            success: false,
            message: "User already exists.".to_string(),
            data: None,
        }));
    }
    
    // Insert user into email-based collection
    let user_data = mongodb::bson::doc! {
        "_id": &email,
        "email": &email,
        "password": &password,
        "websites": [],
        "createdAt": BsonDateTime::now()
    };
    
    email_collection.insert_one(user_data, None).await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    println!("User inserted into {}.{}", email_db_name, email_collection_name);
    
    let response = RegisterResponse {
        success: true,
        message: "User registered successfully.".to_string(),
        data: Some(RegisterData {
            email: email.clone(),
            email_db: email_db_name,
            email_collection: email_collection_name,
        }),
    };
    
    Ok(Json(response))
} 