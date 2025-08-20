use axum::{
    http::{HeaderValue, Method, StatusCode, HeaderMap},
    response::Json,
    routing::{get, post},
    Router,
};
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use hyper::server::conn::http1;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use serde_json::json;
use mongodb::Client;
use std::sync::Arc;
use aws_sdk_s3::{Client as S3Client, Config};
use aws_sdk_s3::config::{Credentials, Region};

// Import modules
mod auth;
mod register;
mod state;
mod jwt;
mod bucket;
mod createwebsite;
use auth::login_handler;
use register::register_handler;
use createwebsite::create_website_handler;
use state::AppState;
use jwt::JwtManager;

// MongoDB connection string (similar to server.js)
const MONGODB_URI: &str = "mongodb+srv://ecommerce:Kathiravan_2004@ecommerce.jc096.mongodb.net/?retryWrites=true&w=majority";

// --- Connect to Cloudflare R2 ---
async fn connect_r2() -> Result<S3Client, Box<dyn std::error::Error + Send + Sync>> {
    let account_id = "065e5715c441540dc89a4218ed83bd75";
    let access_key = "91df97620f07029fe630db1effc2ff15";
    let secret_key = "69f077234da33ce631f8941f65df51ae3fff7f4c53913d0dc04e4fdc873f3093";

    let endpoint_url = format!("https://{}.r2.cloudflarestorage.com", account_id);

    let creds = Credentials::new(access_key, secret_key, None, None, "Static");
    let config = Config::builder()
        .region(Region::new("auto"))
        .endpoint_url(endpoint_url)
        .credentials_provider(creds)
        .build();

    Ok(S3Client::from_conf(config))
}

async fn connect_db() -> Result<Client, mongodb::error::Error> {
    let client = Client::with_uri_str(MONGODB_URI).await?;
    
    // Test the connection
    client
        .database("admin")
        .run_command(mongodb::bson::doc! {"ping": 1}, None)
        .await?;
    
    println!("✅ Connected to MongoDB Atlas");
    Ok(client)
}

async fn setup_database() -> Result<AppState, Box<dyn std::error::Error + Send + Sync>> {
    let client = connect_db().await?;
    let db = client.database("Shopenix");
    
    // Connect to Cloudflare R2
    let r2_client = connect_r2().await?;
    println!("✅ Connected to Cloudflare R2");
    
    let app_state = AppState {
        client: client.clone(),
        db: db.clone(),
        users: db.collection("users"),
        jwt_manager: JwtManager::new(),
        r2_client,
    };
    
    println!("✅ Database collections initialized");
    Ok(app_state)
}

#[tokio::main]
async fn main() {
    // Setup MongoDB connection and R2
    let app_state = match setup_database().await {
        Ok(state) => Arc::new(state),
        Err(e) => {
            eprintln!("❌ Failed to setup services: {}", e);
            return;
        }
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:8080".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::AUTHORIZATION])
        .allow_credentials(true);

    let app = Router::new()
        .route("/api/check", get(check_handler))
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
        .route("/api/session", get(session_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/r2/test", get(test_r2_connection))
        .route("/api/buckets", get(list_buckets_handler))
        .route("/api/user/websites", post(create_website_handler))
        .layer(cors)
        .with_state(app_state.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let listener = TcpListener::bind(addr).await.unwrap();
    println!("✅ Server running at http://{}", addr);

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let app = app.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);

            if let Err(err) = http1::Builder::new()
                .serve_connection(io, TowerToHyperService::new(app))
                .await
            {
                eprintln!("❌ Server error: {:?}", err);
            }
        });
    }
}

async fn check_handler() -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(json!({ "status": "ok1" })))
}

async fn test_r2_connection(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Test R2 connection by listing buckets
    match state.r2_client.list_buckets().send().await {
        Ok(result) => {
            let buckets: Vec<String> = result
                .buckets()
                .unwrap_or_default()
                .iter()
                .filter_map(|bucket| bucket.name().map(|s| s.to_string()))
                .collect();
            
            Ok(Json(json!({
                "success": true,
                "message": "R2 connection successful",
                "buckets": buckets
            })))
        }
        Err(e) => {
            eprintln!("❌ R2 connection test failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_buckets_handler() -> Result<Json<serde_json::Value>, StatusCode> {
    match bucket::list_buckets().await {
        Ok(buckets) => {
            Ok(Json(json!({
                "success": true,
                "buckets": buckets
            })))
        }
        Err(e) => {
            eprintln!("❌ Failed to list buckets: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn session_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Extract token from Authorization header
    let auth_header = headers.get("authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !auth_str.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let token = &auth_str[7..]; // Remove "Bearer " prefix
    
    // Validate token
    let claims = state.jwt_manager.validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Get session data
    let session = state.jwt_manager.get_session(&claims.jti).await
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Check if session is expired
    if chrono::Utc::now() > session.expires_at {
        state.jwt_manager.invalidate_session(&claims.jti).await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    Ok(Json(json!({
        "isAuthenticated": true,
        "user": {
            "email": session.email,
            "websites": session.websites
        },
        "session": {
            "sessionType": session.session_type,
            "sessionValue": session.session_value,
            "expiresAt": session.expires_at.to_rfc3339()
        }
    })))
}

async fn logout_handler(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Extract token from Authorization header
    let auth_header = headers.get("authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    
    let auth_str = auth_header.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    if !auth_str.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    let token = &auth_str[7..]; // Remove "Bearer " prefix
    
    // Validate token to get claims
    let claims = state.jwt_manager.validate_token(token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    // Invalidate session
    state.jwt_manager.invalidate_session(&claims.jti).await;
    
    Ok(Json(json!({
        "success": true,
        "message": "Logged out successfully"
    })))
}
