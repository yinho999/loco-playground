use axum::routing::get;
use axum::{middleware, Extension, Router};
use axum_extra::extract::cookie::{Key, SameSite};
use oauth2::{AuthUrl, TokenUrl};
use playground::app_state::AppState;
use playground::controllers::{
    check_authorized, google_callback, hello_world, homepage, protected,
};
use playground::oauth2_storage::grants::authorization_code::AuthorizationCodeClient;
use playground::oauth2_storage::oauth2_grant::OAuth2ClientGrantEnum;
use playground::oauth2_storage::OAuth2ClientStore;
use sqlx::PgPool;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use time::Duration;
use tokio::sync::Mutex;
use tower_sessions::{Expiry, MemoryStore, Session, SessionManagerLayer};

fn build_oauth_client(client_id: String, client_secret: String) -> OAuth2ClientStore {
    // In prod, http://localhost:8000 would get replaced by whatever your production URL is
    let redirect_url = "http://localhost:8000/api/auth/google_callback".to_string();

    let authorization_code_client = AuthorizationCodeClient::new(
        client_id,
        Some(client_secret),
        "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
        Some("https://www.googleapis.com/oauth2/v3/token".to_string()),
        redirect_url,
        "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
        vec!["https://www.googleapis.com/auth/userinfo.email".to_string()],
        None,
    )
    .unwrap();
    let mut clients = BTreeMap::new();
    clients.insert(
        "google".to_string(),
        OAuth2ClientGrantEnum::AuthorizationCode(Arc::new(Mutex::new(authorization_code_client))),
    );
    let mut clients = OAuth2ClientStore::new(clients);
    clients
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Set up the subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO) // Set the max level to INFO
        .init();
    dotenvy::dotenv()?;
    let google_client_id = dotenvy::var("GOOGLE_CLIENT_ID")?;
    let google_client_secret = dotenvy::var("GOOGLE_CLIENT_SECRET")?;
    let db = PgPool::connect(&dotenvy::var("DATABASE_URL")?).await?;
    sqlx::migrate!()
        .run(&db)
        .await
        .expect("Failed migrations :(");
    let ctx = reqwest::Client::new();

    // create a new instance of our application state
    let app_state = AppState {
        db,
        ctx,
        key: Key::generate(),
    };
    let client = Arc::new(build_oauth_client(
        google_client_id.clone(),
        google_client_secret.clone(),
    ));
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax);

    // Build our application with reduced cloning
    let app = Router::new()
        .route(
            "/api/auth/google_callback",
            get(google_callback), // Efficient cloning due to Arc
        )
        .route(
            "/protected",
            get(protected).route_layer(middleware::from_fn_with_state(
                app_state.clone(), // Efficient cloning due to Arc
                check_authorized,
            )),
        )
        .route("/home", get(homepage))
        .route("/", get(hello_world))
        .with_state(app_state.clone()) // Efficient cloning due to Arc
        .layer(Extension(client)) // No need to clone here if not used elsewhere
        .layer(session_layer);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
