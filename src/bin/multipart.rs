use axum::{
    extract::{multipart::Multipart, State},
    http::StatusCode,
    response::Html,
    routing::post,
    Router,
};
use object_store::{local::LocalFileSystem, ObjectStore, Result as ObjStoreResult, PutResult};
use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use axum::handler::{Handler, HandlerWithoutStateExt};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use object_store::aws::{AmazonS3, AmazonS3Builder};


async fn local_helper(object_store: &LocalFileSystem, path: PathBuf, mut multipart: Multipart) -> ObjStoreResult<(), String> {
    while let Some(field) = multipart.next_field().await.map_err(|_| "Failed to read multipart field".to_string())? {
        if field.name() == Some("file") {
            let uuid = uuid::Uuid::new_v4();
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let file_name = format!("{}-{}", uuid, file_name);
            let new_path = path.join(&file_name);
            let path_string = new_path.to_str().ok_or("Failed to convert path to string".to_string())?;
            let new_path = object_store::path::Path::from(path_string);
            println!("Uploading file to {:?}", new_path);
            let content = field.bytes().await.map_err(|_| "Failed to read file content".to_string())?;
            object_store.put(&new_path, content).await.map_err(|e| {
                eprintln!("Failed to store file: {:?}", e);
                "Failed to store file".to_string()
            })?;
            println!("File uploaded");
            return Ok(());
        }
    }
    Err("No file field in form".to_string())
}

async fn aws_helper(object_store:&AmazonS3, path: PathBuf, mut multipart: Multipart) -> ObjStoreResult<(), String> {
    while let Some(field) = multipart.next_field().await.map_err(|_| "Failed to read multipart field".to_string())? {
        if field.name() == Some("file") {
            let uuid = uuid::Uuid::new_v4();
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            let file_name = format!("{}-{}", uuid, file_name);
            let new_path = path.join(&file_name);
            let path_string = new_path.to_str().ok_or("Failed to convert path to string".to_string())?;
            let new_path = object_store::path::Path::from(path_string);
            println!("Uploading file to {:?}", new_path);
            let content = field.bytes().await.map_err(|_| "Failed to read file content".to_string())?;
            object_store.put(&new_path, content).await.map_err(|e| {
                eprintln!("Failed to store file: {:?}", e);
                "Failed to store file".to_string()
            })?;
            println!("File uploaded");
            return Ok(());
        }
    }
    Err("No file field in form".to_string())
}

async fn upload_local_file_handler(State(state): State<Arc<AppState>>, multipart: Multipart) -> Result<Html<String>, (StatusCode, String)> {
    let object_store = state.clone();
    println!("Uploading file");
    let current_dir = env::current_dir().map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string()))?;
    let upload_path = current_dir.join("uploads");

    println!("Uploading file to {:?}", upload_path);

    local_helper(&object_store.local_object_store, upload_path, multipart).await.map(|_| Html("File uploaded".to_string()))
        .map_err(|e| {
            eprintln!("Failed to store file: {:?}", e);
            (StatusCode::BAD_REQUEST, "Failed to store file".to_string())
        })
}
async fn upload_aws_file_handler(State(state): State<Arc<AppState>>, multipart: Multipart) -> Result<Html<String>, (StatusCode, String)> {
    let object_store = state.clone();
    println!("Uploading file");
    let upload_path = Path::new("").to_path_buf();
    aws_helper(&object_store.aws_object_store, upload_path, multipart).await.map(|_| Html("File uploaded".to_string()))
        .map_err(|e| {
            eprintln!("Failed to store file: {:?}", e);
            (StatusCode::BAD_REQUEST, "Failed to store file".to_string())
        })
}
struct AppState {
    local_object_store: LocalFileSystem,
    aws_object_store: AmazonS3,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv()?;
    let aws_access_key_id = env::var("AWS_ACCESS_KEY_ID")?;
    let aws_secret_access_key = env::var("AWS_SECRET_ACCESS_KEY")?;
    let bucket = env::var("AWS_BUCKET_NAME")?;
    let region = env::var("AWS_BUCKET_REGION")?;

    let aws = AmazonS3Builder::new()
        .with_bucket_name(bucket)
        .with_region(region)
        .with_access_key_id(aws_access_key_id)
        .with_secret_access_key(aws_secret_access_key).build()?;

    let app_state = Arc::new(AppState {
        local_object_store: LocalFileSystem::new(),
        aws_object_store: aws
    });
    // Build our application with a single route
    let app = Router::new()
        .route("/upload/local", post(upload_local_file_handler))
        .route("/upload/aws", post(upload_aws_file_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        )
        .with_state(app_state)
        ;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
