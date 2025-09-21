use mongodb::{Client, Database, Collection, bson::Document};
use std::sync::Arc;
use crate::jwt::JwtManager;
use aws_sdk_s3::Client as S3Client;

pub struct AppState {
    pub client: Client,
    pub db: Database,
    pub users: Collection<Document>,
    pub jwt_manager: JwtManager,
    pub r2_client: S3Client,
    pub aerospike_client: Arc<aerospike::Client>,
} 
