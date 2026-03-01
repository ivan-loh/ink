use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use ink_core::{InkError, InkResult};
use rand::RngCore;
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, RETRY_AFTER, SET_COOKIE};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;

const API_VERSION_20240226: &str = "20240226";
const HEADER_X_SNJS_VERSION: &str = "x-snjs-version";
const SNJS_HEADER_VALUE: &str = concat!("ink/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone)]
pub struct StandardNotesApi {
    base_url: String,
    client: Client,
}

#[derive(Debug, Clone)]
pub struct LoginParamsBundle {
    pub key_params: KeyParamsData,
    pub code_verifier: String,
}

#[derive(Debug, Clone)]
pub struct SignInRequest {
    pub email: String,
    pub server_password: String,
    pub code_verifier: String,
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyParamsData {
    pub identifier: Option<String>,
    pub pw_cost: Option<u64>,
    pub pw_nonce: Option<String>,
    pub version: Option<String>,
    pub pw_salt: Option<String>,
    pub email: Option<String>,
    pub pw_func: Option<String>,
    pub pw_alg: Option<String>,
    pub pw_key_size: Option<u64>,
    pub origination: Option<String>,
    pub created: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionBody {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expiration: i64,
    pub refresh_expiration: i64,
    #[serde(default)]
    pub readonly_access: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub uuid: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignInData {
    pub session: Option<SessionBody>,
    pub token: Option<String>,
    pub user: Option<UserData>,
    pub key_params: Option<KeyParamsData>,
    #[serde(skip)]
    pub access_token_cookie: Option<String>,
    #[serde(skip)]
    pub refresh_token_cookie: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRenewalData {
    pub session: Option<SessionBody>,
    #[serde(skip)]
    pub access_token_cookie: Option<String>,
    #[serde(skip)]
    pub refresh_token_cookie: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncItemInput {
    pub uuid: String,
    pub content_type: String,
    pub content: String,
    pub enc_item_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at_timestamp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_system_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_vault_uuid: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncItem {
    pub uuid: String,
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub enc_item_key: String,
    #[serde(default)]
    pub items_key_id: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub duplicate_of: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub created_at_timestamp: Option<i64>,
    #[serde(default)]
    pub updated_at_timestamp: Option<i64>,
    #[serde(default)]
    pub key_system_identifier: Option<String>,
    #[serde(default)]
    pub shared_vault_uuid: Option<String>,
    #[serde(default)]
    pub user_uuid: Option<String>,
    #[serde(default)]
    pub updated_with_session: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemsSyncRequest {
    #[serde(default)]
    pub items: Vec<SyncItemInput>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub sync_token: Option<String>,
    #[serde(default)]
    pub cursor_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ItemsSyncResponseData {
    #[serde(default)]
    pub retrieved_items: Vec<SyncItem>,
    #[serde(default)]
    pub saved_items: Vec<SyncItem>,
    #[serde(default)]
    pub conflicts: Vec<Value>,
    #[serde(default)]
    pub sync_token: Option<String>,
    #[serde(default)]
    pub cursor_token: Option<String>,
    #[serde(default)]
    pub messages: Vec<Value>,
    #[serde(default)]
    pub shared_vaults: Vec<Value>,
    #[serde(default)]
    pub shared_vault_invites: Vec<Value>,
    #[serde(default)]
    pub notifications: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: Option<ErrorBody>,
    data: Option<ErrorEnvelopeData>,
    message: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    tag: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelopeData {
    error: Option<ErrorBody>,
    message: Option<String>,
    reason: Option<String>,
}

impl StandardNotesApi {
    pub fn new(base_url: &str) -> InkResult<Self> {
        let trimmed = base_url.trim_end_matches('/').to_string();
        if trimmed.is_empty() {
            return Err(InkError::usage("server URL cannot be empty"));
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(format!("ink-cli/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|err| InkError::io(format!("failed to construct API client: {err}")))?;

        Ok(Self {
            base_url: trimmed,
            client,
        })
    }

    pub fn get_login_params(&self, email: &str) -> InkResult<LoginParamsBundle> {
        let email = email.trim();
        if email.is_empty() {
            return Err(InkError::usage("email is required"));
        }

        let (code_verifier, code_challenge) = generate_pkce_pair();
        let body = serde_json::json!({
            "email": email,
            "code_challenge": code_challenge,
        });

        let key_params = self
            .post_json::<KeyParamsData>("/v2/login-params", &body)
            .or_else(|err| match error_status_code(&err) {
                Some(StatusCode::NOT_FOUND)
                | Some(StatusCode::METHOD_NOT_ALLOWED)
                | Some(StatusCode::BAD_REQUEST) => self
                    .post_json::<KeyParamsData>("/v1/login-params", &body)
                    .or_else(|_| {
                        self.get_json::<KeyParamsData>("/v1/login-params", &[("email", email)])
                    }),
                _ => Err(err),
            })?;

        Ok(LoginParamsBundle {
            key_params,
            code_verifier,
        })
    }

    pub fn sign_in(&self, request: &SignInRequest) -> InkResult<SignInData> {
        if request.email.trim().is_empty() || request.server_password.is_empty() {
            return Err(InkError::usage(
                "email and server password are required for sign in",
            ));
        }
        if request.code_verifier.trim().is_empty() {
            return Err(InkError::usage("code verifier is required for sign in"));
        }

        let body = serde_json::json!({
            "api": API_VERSION_20240226,
            "email": request.email,
            "password": request.server_password,
            "ephemeral": request.ephemeral,
            "code_verifier": request.code_verifier,
        });

        let http_response = self
            .client
            .post(self.url("/v2/login"))
            .header(HEADER_X_SNJS_VERSION, SNJS_HEADER_VALUE)
            .json(&body)
            .send()
            .map_err(network_error)?;
        let access_cookie = extract_cookie_from_headers(http_response.headers(), "access_token_");
        let refresh_cookie = extract_cookie_from_headers(http_response.headers(), "refresh_token_");
        let mut response: SignInData = parse_json_response(http_response)?;
        response.access_token_cookie = access_cookie;
        response.refresh_token_cookie = refresh_cookie;

        if response.session.is_none() && response.token.is_none() {
            return Err(InkError::auth(
                "login response did not include a session or token payload",
            ));
        }

        Ok(response)
    }

    pub fn refresh_session(
        &self,
        access_token: &str,
        refresh_token: &str,
        refresh_token_cookie: Option<&str>,
    ) -> InkResult<SessionRenewalData> {
        if access_token.trim().is_empty() || refresh_token.trim().is_empty() {
            return Err(InkError::usage(
                "access token and refresh token are required for session refresh",
            ));
        }

        let is_cookie_based = access_token.starts_with("2:") && refresh_token.starts_with("2:");

        let request = if is_cookie_based {
            let cookie = refresh_token_cookie.ok_or_else(|| {
                InkError::auth(
                    "refresh token cookie missing for cookie-based session; run `ink auth login` again",
                )
            })?;

            self.client
                .post(self.url("/v1/sessions/refresh"))
                .header(HEADER_X_SNJS_VERSION, SNJS_HEADER_VALUE)
                .header("Cookie", cookie)
                .bearer_auth(refresh_token)
                .json(&serde_json::json!({
                    "api": API_VERSION_20240226,
                }))
        } else {
            self.client
                .post(self.url("/v1/sessions/refresh"))
                .header(HEADER_X_SNJS_VERSION, SNJS_HEADER_VALUE)
                .json(&serde_json::json!({
                    "api": API_VERSION_20240226,
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                }))
        };

        let http_response = request.send().map_err(network_error)?;
        let access_cookie = extract_cookie_from_headers(http_response.headers(), "access_token_");
        let refresh_cookie = extract_cookie_from_headers(http_response.headers(), "refresh_token_");
        let mut response: SessionRenewalData = parse_json_response(http_response)?;
        response.access_token_cookie = access_cookie;
        response.refresh_token_cookie = refresh_cookie;
        Ok(response)
    }

    pub fn sign_out(&self, access_token: &str) -> InkResult<()> {
        if access_token.trim().is_empty() {
            return Err(InkError::usage("access token is required for sign out"));
        }

        let url = self.url("/v1/logout");
        let response = self
            .client
            .post(url)
            .bearer_auth(access_token)
            .send()
            .map_err(network_error)?;

        parse_no_content_response(response)
    }

    pub fn sync_items(
        &self,
        access_token: &str,
        access_token_cookie: Option<&str>,
        request: &ItemsSyncRequest,
    ) -> InkResult<ItemsSyncResponseData> {
        if access_token.trim().is_empty() {
            return Err(InkError::auth("access token is required for sync"));
        }

        if access_token.starts_with("2:") && access_token_cookie.is_none() {
            return Err(InkError::auth(
                "access token cookie missing for cookie-based session; run `ink auth login` again",
            ));
        }

        let mut body = serde_json::json!({
            "api": API_VERSION_20240226,
            "items": request.items.clone(),
        });

        if let Some(limit) = request.limit {
            body["limit"] = serde_json::json!(limit);
        }
        if let Some(sync_token) = request.sync_token.as_deref()
            && !sync_token.trim().is_empty()
        {
            body["sync_token"] = serde_json::json!(sync_token);
        }
        if let Some(cursor_token) = request.cursor_token.as_deref()
            && !cursor_token.trim().is_empty()
        {
            body["cursor_token"] = serde_json::json!(cursor_token);
        }

        let mut post = self
            .client
            .post(self.url("/v1/items"))
            .header(HEADER_X_SNJS_VERSION, SNJS_HEADER_VALUE)
            .bearer_auth(access_token)
            .json(&body);

        if let Some(cookie) = access_token_cookie
            && !cookie.trim().is_empty()
        {
            post = post.header("Cookie", cookie);
        }

        parse_json_response(post.send().map_err(network_error)?)
    }

    fn post_json<T: DeserializeOwned>(&self, path: &str, payload: &Value) -> InkResult<T> {
        self.post_json_with_headers(path, payload, &[])
    }

    fn post_json_with_headers<T: DeserializeOwned>(
        &self,
        path: &str,
        payload: &Value,
        headers: &[(&str, String)],
    ) -> InkResult<T> {
        let mut request = self.client.post(self.url(path)).json(payload);
        for (key, value) in headers {
            request = request.header(*key, value);
        }
        parse_json_response(request.send().map_err(network_error)?)
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str, query: &[(&str, &str)]) -> InkResult<T> {
        let request = self.client.get(self.url(path)).query(query);
        parse_json_response(request.send().map_err(network_error)?)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

fn generate_pkce_pair() -> (String, String) {
    let mut random_bytes = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut random_bytes);

    let code_verifier = URL_SAFE.encode(random_bytes);
    let digest = Sha256::digest(code_verifier.as_bytes());
    let digest_hex = hex::encode(digest);
    let code_challenge = URL_SAFE_NO_PAD.encode(digest_hex.as_bytes());

    (code_verifier, code_challenge)
}

fn parse_no_content_response(response: Response) -> InkResult<()> {
    let status = response.status();
    let headers = response.headers().clone();
    if status.is_success() {
        return Ok(());
    }

    let body_text = response.text().unwrap_or_default();
    Err(parse_error_response(status, &body_text, Some(&headers)))
}

fn parse_json_response<T: DeserializeOwned>(response: Response) -> InkResult<T> {
    let status = response.status();
    let headers = response.headers().clone();
    let body_text = response.text().unwrap_or_default();

    if !status.is_success() {
        return Err(parse_error_response(status, &body_text, Some(&headers)));
    }

    let value = serde_json::from_str::<Value>(&body_text)
        .map_err(|err| InkError::sync(format!("failed to decode API response JSON: {err}")))?;

    if let Some(data) = value.get("data")
        && !data.is_null()
        && let Ok(parsed) = serde_json::from_value::<T>(data.clone())
    {
        return Ok(parsed);
    }

    serde_json::from_value::<T>(value).map_err(|err| {
        InkError::sync(format!(
            "failed to map API response to expected shape: {err}"
        ))
    })
}

fn parse_error_response(
    status: StatusCode,
    body_text: &str,
    headers: Option<&HeaderMap>,
) -> InkError {
    let body_trimmed = body_text.trim();
    let fallback = if body_trimmed.is_empty() {
        format!("request failed with status {}", status.as_u16())
    } else {
        format!(
            "request failed with status {}: {}",
            status.as_u16(),
            truncate_for_error(body_trimmed, 240)
        )
    };

    let parsed = serde_json::from_str::<ErrorEnvelope>(body_text).ok();
    let message = parsed
        .as_ref()
        .and_then(|payload| payload.error.as_ref())
        .and_then(|error| error.message.clone())
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|payload| payload.data.as_ref())
                .and_then(|data| data.error.as_ref())
                .and_then(|error| error.message.clone())
        })
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|payload| payload.data.as_ref())
                .and_then(|data| data.message.clone())
        })
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(|payload| payload.data.as_ref())
                .and_then(|data| data.reason.clone())
        })
        .or_else(|| parsed.as_ref().and_then(|payload| payload.message.clone()))
        .or_else(|| parsed.as_ref().and_then(|payload| payload.reason.clone()))
        .unwrap_or(fallback);

    let tagged_message = parsed
        .as_ref()
        .and_then(|payload| payload.error.as_ref())
        .and_then(|error| error.tag.as_ref())
        .map(|tag| format!("{message} ({tag})"))
        .unwrap_or(message);
    let with_retry_after = if status == StatusCode::TOO_MANY_REQUESTS {
        if let Some(seconds) = headers.and_then(extract_retry_after_seconds) {
            format!("{tagged_message} [retry_after_seconds={seconds}]")
        } else {
            tagged_message
        }
    } else {
        tagged_message
    };

    if matches!(
        status,
        StatusCode::BAD_REQUEST
            | StatusCode::UNAUTHORIZED
            | StatusCode::FORBIDDEN
            | StatusCode::UNPROCESSABLE_ENTITY
    ) {
        InkError::auth(format!(
            "{} [http_status={}]",
            with_retry_after,
            status.as_u16()
        ))
    } else {
        InkError::sync(format!(
            "{} [http_status={}]",
            with_retry_after,
            status.as_u16()
        ))
    }
}

fn extract_cookie_from_headers(headers: &HeaderMap, cookie_name_prefix: &str) -> Option<String> {
    for value in headers.get_all(SET_COOKIE) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        let Some(first_segment) = raw.split(';').next() else {
            continue;
        };
        let first_part = first_segment.trim();
        if first_part.starts_with(cookie_name_prefix) {
            return Some(first_part.to_string());
        }
    }

    None
}

fn extract_retry_after_seconds(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.parse::<u64>().ok())
}

fn truncate_for_error(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }

    let truncated: String = input.chars().take(max_chars).collect();
    format!("{truncated}...")
}

fn network_error(err: reqwest::Error) -> InkError {
    InkError::sync(format!("network request failed: {err}"))
}

fn error_status_code(error: &InkError) -> Option<StatusCode> {
    let marker = "[http_status=";
    let start = error.message.find(marker)?;
    let rest = &error.message[start + marker.len()..];
    let end = rest.find(']')?;
    let code = rest[..end].parse::<u16>().ok()?;
    StatusCode::from_u16(code).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_pair_has_expected_shape() {
        let (verifier, challenge) = generate_pkce_pair();
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());
        assert_ne!(verifier, challenge);
        assert!(!challenge.contains('='));
        assert!(
            verifier.contains('='),
            "verifier should use URL base64 padding"
        );
    }
}
