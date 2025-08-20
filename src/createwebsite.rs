use axum::{
    http::{StatusCode, HeaderMap},
    response::Json,
    extract::{State, Json as JsonExtractor},
};
use mongodb::{
    bson::{doc, Document, DateTime as BsonDateTime},
};
use serde::{Serialize};
use std::sync::Arc;
use crate::state::AppState;
use crate::bucket;
use chrono::Utc;
use rand::Rng;

#[derive(Serialize)]
pub struct WebsiteDataSummary {
    pub complete_unique_id: String,
    pub subdomain: String,
}

#[derive(Serialize)]
pub struct CreateWebsiteResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<WebsiteDataSummary>,
}



// Helper: email → db & collection names
pub fn get_email_structure(email: &str) -> (String, String) {
    let first = email.chars().nth(0).unwrap_or('a').to_lowercase().next().unwrap();
    let second = email.chars().nth(1).unwrap_or('a').to_lowercase().next().unwrap();
    let third = email.chars().nth(2).unwrap_or('a').to_lowercase().next().unwrap();

    let db_name = first.to_string();
    let coll_name = format!("{}{}", second, third);

    (db_name, coll_name)
}

// Unique ID generators
pub fn generate_unique_id() -> String {
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789-";
    let start_chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let end_chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let mut id = String::new();
    id.push(start_chars.chars().nth(rng.gen_range(0..start_chars.len())).unwrap());
    for _ in 0..8 {
        id.push(chars.chars().nth(rng.gen_range(0..chars.len())).unwrap());
    }
    id.push(end_chars.chars().nth(rng.gen_range(0..start_chars.len())).unwrap());
    id
}

pub fn generate_complete_unique_id() -> String {
    format!("aaa{}", generate_unique_id())
}

pub async fn create_website_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    JsonExtractor(req): JsonExtractor<serde_json::Value>,
) -> Result<Json<CreateWebsiteResponse>, StatusCode> {

    // ---------- AUTH ----------
    println!("🔹 Step 1: Starting authentication");
    let auth_header = headers.get("authorization").ok_or(StatusCode::UNAUTHORIZED)?;
    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !auth_str.starts_with("Bearer ") {
        println!("❌ Authorization header missing Bearer");
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = &auth_str[7..];

    let claims = state.jwt_manager.validate_token(token).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let session = state.jwt_manager.get_session(&claims.jti).await.ok_or(StatusCode::UNAUTHORIZED)?;
    if Utc::now() > session.expires_at {
        state.jwt_manager.invalidate_session(&claims.jti).await;
        println!("❌ Session expired");
        return Err(StatusCode::UNAUTHORIZED);
    }
    println!("✅ Authentication successful for {}", session.email);
// ---------- SUBDOMAIN CHECK ----------
println!("🔹 Step 2: Checking subdomain");
let subdomain = req.get("subdomain").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
if subdomain.is_empty() {
    println!("❌ Subdomain is empty");
    return Ok(Json(CreateWebsiteResponse {
        success: false,
        message: "Subdomain is required.".to_string(),
        data: None,
    }));
}

let admin_db = state.client.database("adminrecords");
let sub_records = admin_db.collection::<Document>("sub_records");

// Check if subdomain exists
match sub_records.find_one(doc! { "_id": &subdomain }, None).await {
    Ok(Some(_)) => {
        println!("❌ Subdomain '{}' already exists", subdomain);
        return Ok(Json(CreateWebsiteResponse {
            success: false,
            message: "Subdomain already exists.".to_string(),
            data: None,
        }));
    }
    Ok(None) => println!("✅ Subdomain '{}' is available", subdomain),
    Err(e) => {
        eprintln!("❌ MongoDB error checking subdomain '{}': {}", subdomain, e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
}

// Insert subdomain
match sub_records.insert_one(doc! { "_id": &subdomain, "email": &session.email }, None).await {
    Ok(_) => println!("✅ Subdomain '{}' inserted successfully", subdomain),
    Err(e) => {
        eprintln!("❌ MongoDB error inserting subdomain '{}': {}", subdomain, e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
}

// ---------- COMPLETE UNIQUE ID CHECK ----------
println!("🔹 Step 3: Generating unique website ID");
let cid_records = admin_db.collection::<Document>("cid_records");
let mut complete_unique_id = generate_complete_unique_id();
loop {
    match cid_records.find_one(doc! { "_id": &complete_unique_id }, None).await {
        Ok(Some(_)) => {
            complete_unique_id = generate_complete_unique_id(); // retry
        }
        Ok(None) => break,
        Err(e) => {
            eprintln!("❌ MongoDB error checking unique ID '{}': {}", complete_unique_id, e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

match cid_records.insert_one(doc! { "_id": &complete_unique_id, "email": &session.email }, None).await {
    Ok(_) => println!("✅ Unique ID '{}' reserved successfully", complete_unique_id),
    Err(e) => {
        eprintln!("❌ MongoDB error inserting unique ID '{}': {}", complete_unique_id, e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
}

    // ---------- UPDATE USER PROFILE ----------
    println!("🔹 Step 4: Updating user profile");
    let (email_db_name, email_coll_name) = get_email_structure(&session.email);
    let email_db = state.client.database(&email_db_name);
    let email_coll = email_db.collection::<Document>(&email_coll_name);

    email_coll.update_one(
        doc! { "_id": &session.email },
        doc! { "$push": { 
            "websites": { 
                "complete_unique_id": &complete_unique_id,
                "subdomain": &subdomain
            }
        }},
        None
    ).await.map_err(|e| {
        eprintln!("❌ Failed to update user profile with new website: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    println!("✅ User profile updated with new website");

    // ---------- CREATE WEBSITE DB ----------
    println!("🔹 Step 5: Creating website database");
    let website_db = state.client.database(&complete_unique_id);
    let products_col = website_db.collection::<Document>("products");
    products_col.insert_one(doc! {
        "name": "Sample Product",
        "price": 0,
        "created_at": BsonDateTime::now()
    }, None).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    println!("✅ Website database created with sample product");

    // ---------- CREATE CLOUDFLARE R2 BUCKET ----------
    println!("🔹 Step 6: Creating R2 bucket");
    let bucket_created = match bucket::create_bucket(&complete_unique_id).await {
        Ok(_) => {
            println!("✅ R2 bucket '{}' created", complete_unique_id);
            true
        }
        Err(e) => {
            eprintln!("❌ Failed to create R2 bucket '{}': {}", complete_unique_id, e);
            false
        }
    };

    // ---------- ATTACH CUSTOM DOMAIN ----------
    println!("🔹 Step 7: Attaching custom domain");
    let domain_attached = if bucket_created {
        let full_domain = format!("{}", subdomain);
        match bucket::attach_custom_domain(&complete_unique_id, &full_domain).await {
            Ok(_) => {
                println!("✅ Custom domain '{}' attached", full_domain);
                true
            }
            Err(e) => {
                eprintln!("❌ Failed to attach domain '{}': {}", full_domain, e);
                false
            }
        }
    } else {
        false
    };

    // ---------- RESPONSE ----------
    println!("🔹 Step 8: Returning response");
    Ok(Json(CreateWebsiteResponse {
        success: true,
        message: "Website created successfully.".to_string(),
        data: Some(WebsiteDataSummary {
            complete_unique_id,
            subdomain,
        }),
    }))
}

