use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use json_patch::Patch;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};
use std::error::Error;
use std::sync::Arc;

struct AppState {
    db: sqlx::PgPool,
}

#[derive(Clone, Serialize, Deserialize, FromRow, Debug)]
struct User {
    email: String,
}

// Create user route
/*
POST / HTTP/1.1
Host: localhost:8000
Content-Type: application/json
Content-Length: 32

{
    "email":"test@gmail.com"
}
 */
async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(user): Json<User>,
) -> Result<Response, (StatusCode, String)> {
    // Insert user into database and get the id
    let result = sqlx::query!(
        "INSERT INTO users (email) VALUES ($1) RETURNING id",
        user.email
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    println!("User id: {:?}", result.id);
    Ok(Response::new(Body::from(result.id.to_string())))
}

// Get user route
/*
GET /1 HTTP/1.1
Host: localhost:8000
*/
async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    // Get user from database
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    println!("User: {:?}", user);
    Ok((StatusCode::OK, format!("User: {:?}", user)))
}

// Patch user route
/*
PATCH /1 HTTP/1.1
Host: localhost:8000
Content-Type: application/json-patch+json
Content-Length: 102
[
    {
        "op": "replace",
        "path": "/email",
        "value": "test@outlook.com"
    }
]
*/
async fn patch_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i32>,
    Json(params): Json<Patch>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    // Get user from database
    let mut user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    println!("User: {:?}", user);
    let mut user_json = serde_json::to_value(&user).unwrap();
    json_patch::patch(&mut user_json, &params)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    user = serde_json::from_value(user_json).unwrap();
    // Update user in database
    sqlx::query!("UPDATE users SET email = $1 WHERE id = $2", user.email, id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    println!("User: {:?}", user);
    Ok((StatusCode::OK, format!("User: {:?}", user)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenvy::dotenv()?;

    let db = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    // Build our application with a single route
    let app = Router::new()
        .route("/", post(create_user))
        .route("/:id", get(get_user))
        .route("/:id", patch(patch_user))
        .with_state(Arc::new(AppState { db }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
    Ok(())
}
