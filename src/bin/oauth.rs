use axum::routing::get;
use axum::{middleware, Extension, Router};
use axum_extra::extract::cookie::Key;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use playground::app_state::AppState;
use playground::controllers::{
    check_authorized, google_callback, hello_world, homepage, protected,
};
use sqlx::PgPool;
use std::error::Error;
use std::sync::Arc;

fn build_oauth_client(client_id: String, client_secret: String) -> BasicClient {
    // In prod, http://localhost:8000 would get replaced by whatever your production URL is
    let redirect_url = "http://localhost:8000/api/auth/google_callback".to_string();

    // If you're not using Google OAuth, you can use whatever the relevant auth/token URL is for your given OAuth service
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
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
    let client = build_oauth_client(google_client_id.clone(), google_client_secret.clone());
    // build our application
    let app = Router::new()
        .route(
            "/api/auth/google_callback",
            get(google_callback)
                .layer(Extension(client))
                .with_state(app_state.clone()),
        )
        .route(
            "/protected",
            get(protected)
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    check_authorized,
                ))
                .with_state(app_state.clone()),
        )
        .route(
            "/home",
            get(homepage).layer(Extension(google_client_id.clone())),
        )
        .route("/", get(hello_world));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
