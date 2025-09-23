use std::time::Instant;
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
// ...existing code...
use aws_sdk_s3::{Client as S3Client, Config};
use aws_sdk_s3::config::{Credentials, Region};
use serde_json::Value;
use axum::{
    extract::{State}
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use tokio::process::Command;

use std::{fs, path::PathBuf};

#[derive(Deserialize)]
struct CodeInput {
    code: String,
}
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

// --- Connect to Aerospike ---
use aerospike::{Client as AerospikeClient, ClientPolicy};
use std::env;
use std::sync::Arc;

async fn connect_aerospike() -> Result<Arc<AerospikeClient>, Box<dyn std::error::Error + Send + Sync>> {
    let hosts = env::var("AERO")
        .map_err(|_| "Missing environment variable: AERO")?;

    println!("Aerospike at {}", hosts);

    let cpolicy = ClientPolicy::default();

    // ✅ Parse host:port into Host struct
    let host = Host::from_string(&hosts)?;

    let client = AerospikeClient::new(&cpolicy, &[host])
        .map_err(|e| format!("Aerospike connection error: {}", e))?;

    println!("✅ Connected to Aerospike at {}", hosts);

    Ok(Arc::new(client))
}

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

    // Connect to Aerospike
    let aerospike_client = connect_aerospike().await?;

    let app_state = AppState {
        client: client.clone(),
        db: db.clone(),
        users: db.collection("users"),
        jwt_manager: JwtManager::new(),
        r2_client,
        aerospike_client,
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
    .allow_origin([
        HeaderValue::from_static("https://solidjs-zjho.vercel.app")
    ])
    .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
    .allow_headers([
        axum::http::header::CONTENT_TYPE,
        axum::http::header::AUTHORIZATION,
    ])
    .allow_credentials(true);

    use aerospike::{as_key, as_bin, Bins, WritePolicy, ReadPolicy, operations};
    let app = Router::new()
        .route("/api/check", get(check_handler))
        .route("/login", post(login_handler))
        .route("/register", post(register_handler))
        .route("/api/session", get(session_handler))
        .route("/api/logout", post(logout_handler))
        .route("/api/r2/test", get(test_r2_connection))
        .route("/api/buckets", get(list_buckets_handler))
        .route("/api/user/websites", post(create_website_handler))
        .route("/api/transform", post(transform_handler))
        .route("/api/aerospike/test", get(aerospike_test_handler))
        .route("/api/aerospike/bulk-test", get(aerospike_bulk_test_handler))
        .layer(cors)
        .with_state(app_state.clone());
    // Aerospike CRUD test handler
    async fn aerospike_test_handler(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, StatusCode> {
        let client = &state.aerospike_client;
        let wpolicy = WritePolicy::default();
        let rpolicy = ReadPolicy::default();
        let key = as_key!("test1", "test1", "rust_test1");

        // Create/Update
        let bins = [
            as_bin!("int1", 123),
            as_bin!("str1", "Hello, Aerospike!"),
        ];
        client.put(&wpolicy, &key, &bins).map_err(|e| {
            eprintln!("Aerospike put error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        // Read
        let rec = client.get(&rpolicy, &key, Bins::All).map_err(|e| {
            eprintln!("Aerospike get error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let record_str = format!("{}", rec);

        // Update (operate)
        let bin = as_bin!("int1", 999);
        let ops = &vec![operations::put(&bin), operations::get()];
        let op_rec = client.operate(&wpolicy, &key, ops).map_err(|e| {
            eprintln!("Aerospike operate error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let op_record_str = format!("{}", op_rec);

        // Delete
        let existed = client.delete(&wpolicy, &key).map_err(|e| {
            eprintln!("Aerospike delete error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        Ok(Json(json!({
            "put_record": record_str,
            "operate_record": op_record_str,
            "delete_existed": existed,
        })))
    }
 
    async fn aerospike_bulk_test_handler(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, StatusCode> {
        let client = &state.aerospike_client;
        let wpolicy = WritePolicy::default();
        let rpolicy = ReadPolicy::default();
        let mut write_latencies = Vec::new();
        let mut write_results = Vec::new();
        let total_write_start = Instant::now();
        for i in 0..=1000 {
            let key = as_key!("test", "test", format!("rust_test_{}", i));
            let bins = [as_bin!("val", i)];
            let start = Instant::now();
            let res = client.put(&wpolicy, &key, &bins);
            let elapsed = start.elapsed().as_millis();
            write_latencies.push(elapsed);
            write_results.push(res.is_ok());
            println!("Write key rust_test_{} latency: {} ms", i, elapsed);
        }
        let total_write_latency = total_write_start.elapsed().as_millis();
        println!("Total write latency for 101 keys: {} ms", total_write_latency);

        // Read a specific key (e.g., rust_test_42)
        let read_key = as_key!("test", "test", "rust_test_42");
        let read_start = Instant::now();
        let rec = client.get(&rpolicy, &read_key, Bins::All);
        let read_latency = read_start.elapsed().as_millis();
        println!("Read key rust_test_42 latency: {} ms", read_latency);
        let read_ok = rec.is_ok();
        let read_val = rec.ok().map(|r| format!("{}", r));

        Ok(Json(json!({
            "write_latencies_ms": write_latencies,
            "total_write_latency_ms": total_write_latency,
            "write_results": write_results,
            "read_latency_ms": read_latency,
            "read_ok": read_ok,
            "read_val": read_val,
        })))
    }
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


async fn transform_handler(
    State(_state): State<Arc<AppState>>,
    Json(payload): Json<CodeInput>,
) -> Result<String, (axum::http::StatusCode, String)> {
    // Temp dir
    let temp_dir = PathBuf::from("temp");
    fs::create_dir_all(&temp_dir).map_err(internal_err)?;

    // Fixed input/output files (since you said not per-request unique)
    let infile = temp_dir.join("input.tsx");
    let outfile = temp_dir.join("output.js");

    // Write request code into input.tsx
    fs::write(&infile, &payload.code).map_err(internal_err)?;

    // Run esbuild
    let output = Command::new("node")
        .arg("esbuild.js")
        .arg(&infile)
        .arg(&outfile)
        .output()
        .await
        .map_err(internal_err)?;

    if output.status.success() {
        let js_code = fs::read_to_string(&outfile).map_err(internal_err)?;
        Ok(js_code)
    } else {
        let err = String::from_utf8_lossy(&output.stderr).to_string();
        Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, err))
    }
}

fn internal_err<E: std::fmt::Display>(e: E) -> (axum::http::StatusCode, String) {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
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
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Json<Value>, StatusCode> {
    // --- Try cookie first ---
    let token = jar.get("session_token").map(|c| c.value().to_string());

    // --- Fallback: Authorization header ---
    let token = token.or_else(|| {
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    });

    let token: String = match token {
        Some(t) => t.to_string(),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = state
        .jwt_manager
        .validate_token(&token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let session = state
        .jwt_manager
        .get_session(&claims.jti)
        .await
        .ok_or(StatusCode::UNAUTHORIZED)?;

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
    jar: CookieJar,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let token = jar.get("session_token").map(|c| c.value().to_string()).or_else(|| {
        headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.to_string())
    });

    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let claims = state
        .jwt_manager
        .validate_token(&token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    state.jwt_manager.invalidate_session(&claims.jti).await;

    // --- Clear cookie on logout ---
    let cookie = axum_extra::extract::cookie::Cookie::build(("session_token", ""))
        .domain(".myapp.local")
        .path("/")
        .http_only(true)
        .expires(time::OffsetDateTime::UNIX_EPOCH)
        .finish();

    let mut jar = jar;
    jar = jar.add(cookie);

    Ok(Json(json!({ "success": true, "message": "Logged out successfully" })))
}
