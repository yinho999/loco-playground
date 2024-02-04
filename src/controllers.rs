use crate::app_state::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect};
use axum::{http, Extension};
use axum_extra::extract::PrivateCookieJar;
use chrono::{Duration, Local};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{AuthorizationCode, TokenResponse};
use serde::Deserialize;
use tracing::{error, info};

pub async fn homepage(Extension(oauth_id): Extension<String>) -> Html<String> {
    info!("Oauth ID: {}", oauth_id);
    Html(format!("<p>Welcome!</p>
    
    <a href=\"https://accounts.google.com/o/oauth2/v2/auth?scope=openid%20profile%20email&client_id={oauth_id}&response_type=code&redirect_uri=http://localhost:8000/api/auth/google_callback\">
    Click here to sign into Google!
     </a>"))
}

pub async fn hello_world() -> &'static str {
    "Hello world!"
}
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
}

#[derive(Deserialize, sqlx::FromRow, Clone, Debug)]
pub struct UserProfile {
    email: String,
}

pub async fn google_callback(
    // Extract the state from the app
    State(state): State<AppState>,
    // Extract the private cookie jar from the request
    jar: PrivateCookieJar,
    // Extract the query parameters from the request
    Query(query): Query<AuthRequest>,
    // Extract the oauth client from the app
    Extension(oauth_client): Extension<BasicClient>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    // Exchange the code with a token
    let token = match oauth_client
        .exchange_code(AuthorizationCode::new(query.code))
        .request_async(async_http_client)
        .await
    {
        Ok(res) => res,
        Err(e) => {
            error!("An error occurred while exchanging the code: {e}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };
    // Checking and getting the user's profile from Google
    let profile = match state
        .ctx
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(token.access_token().secret().to_owned())
        .send()
        .await
    {
        Ok(res) => res,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    };

    // Parse the user's profile
    let profile = profile.json::<UserProfile>().await.unwrap();
    info!("Profile: {profile:?}");
    // Set the cookie
    let secs: i64 = token.expires_in().unwrap().as_secs().try_into().unwrap();
    // Set the cookie to expire when the token expires
    let max_age = Local::now().naive_local() + Duration::seconds(secs);
    // Create the cookie with the session id, domain, path, and secure flag from the token and profile
    let cookie = axum_extra::extract::cookie::Cookie::build((
        "sid",
        token.access_token().secret().to_owned(),
    ))
    .domain("localhost")
    .path("/")
    // only for testing purposes, toggle this to true in production
    .secure(false)
    .http_only(true)
    .max_age(time::Duration::seconds(secs));

    // Insert the user into the database
    if let Err(e) =
        sqlx::query("INSERT INTO users (email) VALUES ($1) ON CONFLICT (email) DO NOTHING")
            .bind(profile.email.clone())
            .execute(&state.db)
            .await
    {
        error!("Error while trying to make account: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error trying to create account: {e}"),
        ));
    }

    // Insert the session into the database
    if let Err(e) = sqlx::query(
        r#"INSERT INTO sessions (user_id, session_id, expires_at) VALUES (
        (SELECT ID FROM USERS WHERE email = $1 LIMIT 1),
         $2, $3)
        ON CONFLICT (user_id) DO UPDATE SET 
        session_id = excluded.session_id, 
        expires_at = excluded.expires_at"#,
    )
    .bind(profile.email)
    .bind(token.access_token().secret().to_owned())
    .bind(max_age)
    .execute(&state.db)
    .await
    {
        error!("Error while trying to make session: {e}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Error trying to create session: {e}"),
        ));
    }
    // Redirect the user to the protected page
    let jar = jar.add(cookie);
    info!("{jar:?}");
    Ok((jar, Redirect::to("/protected")))
}
pub async fn check_authorized(
    State(state): State<AppState>,
    jar: PrivateCookieJar,
    mut req: http::Request<Body>,
    next: Next,
) -> Result<impl IntoResponse, impl IntoResponse> {
    // return early if no cookie exists
    let Some(cookie) = jar.get("sid").map(|cookie| cookie.value().to_owned()) else {
        info!("No cookie found");
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized!".to_string()));
    };

    let res = match sqlx::query_as::<_, UserProfile>(
        "SELECT 
        users.email
        FROM sessions 
        LEFT JOIN USERS ON sessions.user_id = users.id
        WHERE sessions.session_id = $1 
        LIMIT 1",
    )
    .bind(cookie)
    .fetch_one(&state.db)
    .await
    {
        Ok(res) => res,
        Err(e) => {
            // if user has cookie but doesn't match, return forbidden
            return Err((StatusCode::UNAUTHORIZED, e.to_string()));
        }
    };

    // Initialise struct - feel free to extend this if you grabbed more information from the OIDC endpoint
    let user = UserProfile { email: res.email };

    // Grab extensions as mutable and insert the UserProfile struct
    req.extensions_mut().insert(user);

    // Run the endpoint with the added extension
    Ok(next.run(req).await)
}

pub async fn protected(Extension(user): Extension<UserProfile>) -> impl IntoResponse {
    (StatusCode::OK, user.email)
}
