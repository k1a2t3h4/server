use std::error::Error;
use serde_json::json;

pub async fn create_bucket(bucket: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let account_id = "065e5715c441540dc89a4218ed83bd75";
    let cf_auth_email = "kathiravankumar2004@gmail.com";
    let cf_auth_key = "1e37b0d0c8b49400bcad2a34946c8009c3d41";

    let list_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets",
        account_id
    );

    let client = reqwest::Client::new();

    // 1️⃣ Check if the bucket already exists
    let resp = client
        .get(&list_url)
        .header("X-Auth-Email", cf_auth_email)
        .header("X-Auth-Key", cf_auth_key)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(arr) = resp.get("result").and_then(|r| r.as_array()) {
        if arr.iter().any(|b| b.get("name").and_then(|n| n.as_str()) == Some(bucket)) {
            println!("✅ Bucket '{}' already exists", bucket);
            return Ok(());
        }
    }

    // 2️⃣ Create the bucket if not found
    println!("📦 Creating bucket '{}'", bucket);
    let create_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets",
        account_id
    );

    let create_resp = client
        .post(&create_url)
        .header("Content-Type", "application/json")
        .header("X-Auth-Email", cf_auth_email)
        .header("X-Auth-Key", cf_auth_key)
        .json(&json!({ "name": bucket }))
        .send()
        .await?
        .text()
        .await?;

    println!("Bucket create response: {}", create_resp);
    Ok(())
}

pub async fn attach_custom_domain(bucket: &str, domain: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    let account_id = "065e5715c441540dc89a4218ed83bd75";
    let cf_auth_email = "kathiravankumar2004@gmail.com";
    let cf_auth_key = "1e37b0d0c8b49400bcad2a34946c8009c3d41";
    let zone_id = "7b6ed4275a6c69b5d6e59db038f607dd";

    let client = reqwest::Client::new();
    let url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets/{}/domains/custom",
        account_id, bucket
    );

    let res = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Auth-Email", cf_auth_email)
        .header("X-Auth-Key", cf_auth_key)
        .json(&json!({
            "domain": domain,
            "enabled": true,
            "zoneId": zone_id
        }))
        .send()
        .await?;

    println!("Attach custom domain response: {:?}", res.text().await?);
    Ok(())
}

pub async fn list_buckets() -> Result<Vec<String>, Box<dyn Error + Send + Sync>> {
    let account_id = "065e5715c441540dc89a4218ed83bd75";
    let cf_auth_email = "kathiravankumar2004@gmail.com";
    let cf_auth_key = "1e37b0d0c8b49400bcad2a34946c8009c3d41";

    let list_url = format!(
        "https://api.cloudflare.com/client/v4/accounts/{}/r2/buckets",
        account_id
    );

    let client = reqwest::Client::new();

    let resp = client
        .get(&list_url)
        .header("X-Auth-Email", cf_auth_email)
        .header("X-Auth-Key", cf_auth_key)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let buckets: Vec<String> = resp
        .get("result")
        .and_then(|r| r.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|b| b.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
        .collect();

    Ok(buckets)
} 