use std::ops::{Deref, DerefMut};
use std::{collections::HashMap, time::Instant};

use oauth2::basic::BasicTokenResponse;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, url, url::Url, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::Response;
use subtle::ConstantTimeEq;

use crate::oauth2_storage::error::{OAuth2ClientError, OAuth2ClientResult};

/// A struct that holds the OAuth2 client and the profile URL. - For
/// Authorization Code Grant
pub struct AuthorizationCodeClient {
    pub oauth2: BasicClient,
    pub profile_url: url::Url,
    pub http_client: reqwest::Client,
    pub flow_states: HashMap<String, (PkceCodeVerifier, Instant)>,
}

impl AuthorizationCodeClient {
    /// Create a new instance of `OAuth2Client`.
    pub fn new(
        client_id: String,
        client_secret: Option<String>,
        auth_url: String,
        token_url: Option<String>,
        redirect_url: String,
        profile_url: String,
    ) -> OAuth2ClientResult<Self> {
        let client_id = ClientId::new(client_id);
        let client_secret = if let Some(client_secret) = client_secret {
            Some(ClientSecret::new(client_secret))
        } else {
            None
        };
        let auth_url = AuthUrl::new(auth_url)?;
        let token_url = if let Some(token_url) = token_url {
            Some(TokenUrl::new(token_url)?)
        } else {
            None
        };
        let redirect_url = RedirectUrl::new(redirect_url)?;
        let oauth2 = BasicClient::new(client_id, client_secret, auth_url, token_url)
            .set_redirect_uri(redirect_url);
        let profile_url = url::Url::parse(&profile_url)?;
        Ok(Self {
            oauth2,
            profile_url,
            http_client: reqwest::Client::new(),
            flow_states: HashMap::new(),
        })
    }
    fn remove_expire_flow(&mut self) {
        // Remove expired tokens
        self.flow_states.retain(|_, (_, created_at)| {
            created_at.elapsed() < std::time::Duration::from_secs(10 * 60)
        });
    }
}

fn constant_time_compare(a: &str, b: &str) -> bool {
    // Convert the strings to bytes for comparison.
    // Note: This assumes both slices are of the same length.
    // You might want to handle differing lengths explicitly, depending on your
    // security requirements.
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[async_trait::async_trait]
pub trait AuthorizationCodeGrantTrait: Send + Sync {
    fn get_authorization_code_client(&mut self) -> &mut AuthorizationCodeClient;
    /// Get authorization URL
    fn get_authorization_url(&mut self) -> (Url, CsrfToken) {
        let client = self.get_authorization_code_client();
        // Clear outdated flow states
        client.remove_expire_flow();

        // Generate a PKCE challenge.
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate the full authorization URL.
        let (auth_url, csrf_token) = client
            .oauth2
            .authorize_url(CsrfToken::new_random)
            // Set the desired scopes.
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            // .add_scope(Scope::new("write".to_string()))
            // Set the PKCE code challenge.
            .set_pkce_challenge(pkce_challenge)
            .url();
        // Store the CSRF token, PKCE Verifier and the time it was created.
        let csrf_secret = csrf_token.secret().clone();
        client
            .flow_states
            .insert(csrf_secret.clone(), (pkce_verifier, Instant::now()));
        (auth_url, csrf_token)
    }

    async fn verify_user_with_code(
        &mut self,
        code: String,
        state: String,
        csrf_token: String,
    ) -> OAuth2ClientResult<(BasicTokenResponse, Response)> {
        let client = self.get_authorization_code_client();
        // Clear outdated flow states
        client.remove_expire_flow();
        // Compare csrf token, use subtle to prevent time attack
        if !constant_time_compare(&csrf_token, &state) {
            return Err(OAuth2ClientError::CsrfTokenError);
        }
        // Get the pkce_verifier for exchanging code
        let (pkce_verifier, _) = match client.flow_states.remove(&csrf_token) {
            None => {
                return Err(OAuth2ClientError::CsrfTokenError);
            }
            Some(item) => item,
        };
        // Exchange the code with a token
        let token = client
            .oauth2
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .request_async(async_http_client)
            .await?;
        let profile = client
            .http_client
            .get(client.profile_url.clone())
            .bearer_auth(token.access_token().secret().to_owned())
            .send()
            .await?;
        Ok((token, profile))
    }
}
impl AuthorizationCodeGrantTrait for AuthorizationCodeClient {
    fn get_authorization_code_client(&mut self) -> &mut AuthorizationCodeClient {
        self
    }
}