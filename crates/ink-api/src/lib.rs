use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use ink_core::{ErrorKind, InkError, InkResult};
use rand::RngCore;
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, RETRY_AFTER, SET_COOKIE};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::time::Duration;
use tracing::{Level, debug};

const API_VERSION_20240226: &str = "20240226";
const HEADER_X_SNJS_VERSION: &str = "x-snjs-version";
const SNJS_HEADER_VALUE: &str = concat!("ink/", env!("CARGO_PKG_VERSION"));
const ENV_API_DEBUG_VERBOSE: &str = "INK_API_DEBUG_VERBOSE";
const ENV_API_DEBUG_RAW: &str = "INK_API_DEBUG_RAW";
const ENV_API_DEBUG_MAX_CHARS: &str = "INK_API_DEBUG_MAX_CHARS";
const ENV_API_REFRESH_FALLBACK: &str = "INK_API_REFRESH_FALLBACK";
const ENV_API_REFRESH_RETRY_ATTEMPTS: &str = "INK_API_REFRESH_RETRY_ATTEMPTS";
const ENV_API_REFRESH_RETRY_BASE_DELAY_MS: &str = "INK_API_REFRESH_RETRY_BASE_DELAY_MS";
const DEFAULT_API_DEBUG_MAX_CHARS: usize = 2000;
const DEFAULT_API_REFRESH_RETRY_ATTEMPTS: usize = 2;
const DEFAULT_API_REFRESH_RETRY_BASE_DELAY_MS: u64 = 100;

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
    #[serde(default, deserialize_with = "deserialize_bool_like_to_default")]
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
    #[serde(skip)]
    pub mode_used: Option<RefreshTransportMode>,
    #[serde(skip)]
    pub fallback_attempted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTransportMode {
    TokenBody,
    DualCookieTokenBody,
}

impl RefreshTransportMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenBody => "token_body",
            Self::DualCookieTokenBody => "dual_cookie_token_body",
        }
    }
}

impl std::fmt::Display for RefreshTransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct RefreshSessionRequest<'a> {
    pub access_token: &'a str,
    pub refresh_token: &'a str,
    pub access_token_cookie: Option<&'a str>,
    pub refresh_token_cookie: Option<&'a str>,
    pub preferred_mode: Option<RefreshTransportMode>,
    pub allow_fallback: bool,
}

impl<'a> RefreshSessionRequest<'a> {
    pub fn new(access_token: &'a str, refresh_token: &'a str) -> Self {
        Self {
            access_token,
            refresh_token,
            access_token_cookie: None,
            refresh_token_cookie: None,
            preferred_mode: None,
            allow_fallback: true,
        }
    }

    pub fn with_access_token_cookie(mut self, cookie: Option<&'a str>) -> Self {
        self.access_token_cookie = cookie;
        self
    }

    pub fn with_refresh_token_cookie(mut self, cookie: Option<&'a str>) -> Self {
        self.refresh_token_cookie = cookie;
        self
    }

    pub fn with_preferred_mode(mut self, mode: Option<RefreshTransportMode>) -> Self {
        self.preferred_mode = mode;
        self
    }

    pub fn with_fallback(mut self, enabled: bool) -> Self {
        self.allow_fallback = enabled;
        self
    }
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

fn deserialize_nullable_string_to_default<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.unwrap_or_default())
}

fn deserialize_bool_like_to_default<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolLike {
        Bool(bool),
        Int(i64),
        Str(String),
    }

    let value = Option::<BoolLike>::deserialize(deserializer)?;
    match value {
        None => Ok(false),
        Some(BoolLike::Bool(value)) => Ok(value),
        Some(BoolLike::Int(value)) => Ok(value != 0),
        Some(BoolLike::Str(value)) => {
            let normalized = value.trim().to_ascii_lowercase();
            Ok(matches!(normalized.as_str(), "1" | "true" | "yes" | "on"))
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SyncItem {
    pub uuid: String,
    #[serde(default, deserialize_with = "deserialize_nullable_string_to_default")]
    pub content_type: String,
    #[serde(default, deserialize_with = "deserialize_nullable_string_to_default")]
    pub content: String,
    #[serde(default, deserialize_with = "deserialize_nullable_string_to_default")]
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
        request: &RefreshSessionRequest<'_>,
    ) -> InkResult<SessionRenewalData> {
        if request.access_token.trim().is_empty() || request.refresh_token.trim().is_empty() {
            return Err(InkError::usage(
                "access token and refresh token are required for session refresh",
            ));
        }

        let mut candidates = refresh_mode_candidates(request);
        let allow_fallback = request.allow_fallback && refresh_fallback_enabled();
        if !allow_fallback {
            candidates.truncate(1);
        }

        let primary_mode = candidates[0];
        debug!(
            target: "ink_api::http",
            mode = %primary_mode,
            allow_fallback = allow_fallback,
            has_preferred_mode = request.preferred_mode.is_some(),
            "refresh transport selected"
        );

        match self.refresh_session_with_mode(request, primary_mode) {
            Ok(mut response) => {
                response.mode_used = Some(primary_mode);
                response.fallback_attempted = false;
                Ok(response)
            }
            Err(primary_error) => {
                let Some(fallback_mode) = candidates.get(1).copied() else {
                    return Err(primary_error);
                };

                if !is_contract_mismatch_auth_error(&primary_error) {
                    return Err(primary_error);
                }

                debug!(
                    target: "ink_api::http",
                    primary_mode = %primary_mode,
                    fallback_mode = %fallback_mode,
                    error = %primary_error.message,
                    "refresh transport fallback attempt"
                );

                let mut fallback_response =
                    self.refresh_session_with_mode(request, fallback_mode)?;
                fallback_response.mode_used = Some(fallback_mode);
                fallback_response.fallback_attempted = true;
                Ok(fallback_response)
            }
        }
    }

    fn refresh_session_with_mode(
        &self,
        request: &RefreshSessionRequest<'_>,
        mode: RefreshTransportMode,
    ) -> InkResult<SessionRenewalData> {
        let max_retries = refresh_retry_attempts();
        let mut retry_attempt = 0usize;

        loop {
            match self.refresh_session_with_mode_once(request, mode) {
                Ok(response) => return Ok(response),
                Err(error) => {
                    let retryable = is_refresh_retryable_error(&error);
                    if !retryable || retry_attempt >= max_retries {
                        return Err(error);
                    }

                    retry_attempt += 1;
                    let delay = refresh_retry_delay(retry_attempt, &error);
                    debug!(
                        target: "ink_api::http",
                        mode = %mode,
                        retry_attempt = retry_attempt,
                        max_retries = max_retries,
                        delay_ms = delay.as_millis() as u64,
                        error = %error.message,
                        "refresh transport retry"
                    );
                    std::thread::sleep(delay);
                }
            }
        }
    }

    fn refresh_session_with_mode_once(
        &self,
        request: &RefreshSessionRequest<'_>,
        mode: RefreshTransportMode,
    ) -> InkResult<SessionRenewalData> {
        let mut post = self
            .client
            .post(self.url("/v1/sessions/refresh"))
            .header(HEADER_X_SNJS_VERSION, SNJS_HEADER_VALUE);

        if mode == RefreshTransportMode::DualCookieTokenBody {
            let access_cookie = request.access_token_cookie.and_then(non_empty_trimmed_str).ok_or_else(|| {
                InkError::auth(
                    "access token cookie missing for dual-cookie refresh transport; run `ink auth login` again",
                )
            })?;
            let refresh_cookie = request
                .refresh_token_cookie
                .and_then(non_empty_trimmed_str)
                .ok_or_else(|| {
                    InkError::auth(
                        "refresh token cookie missing for dual-cookie refresh transport; run `ink auth login` again",
                    )
                })?;
            post = post.header("Cookie", format!("{access_cookie}; {refresh_cookie}"));
        }

        let http_response = post
            .json(&serde_json::json!({
                "access_token": request.access_token,
                "refresh_token": request.refresh_token,
            }))
            .send()
            .map_err(network_error)?;
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

fn refresh_mode_candidates(request: &RefreshSessionRequest<'_>) -> Vec<RefreshTransportMode> {
    if let Some(mode) = request.preferred_mode {
        return vec![mode, alternate_refresh_mode(mode)];
    }

    let has_dual_tokens =
        request.access_token.starts_with("2:") && request.refresh_token.starts_with("2:");
    let has_dual_cookies = request
        .access_token_cookie
        .and_then(non_empty_trimmed_str)
        .is_some()
        && request
            .refresh_token_cookie
            .and_then(non_empty_trimmed_str)
            .is_some();

    if has_dual_tokens && has_dual_cookies {
        vec![
            RefreshTransportMode::DualCookieTokenBody,
            RefreshTransportMode::TokenBody,
        ]
    } else {
        vec![
            RefreshTransportMode::TokenBody,
            RefreshTransportMode::DualCookieTokenBody,
        ]
    }
}

fn alternate_refresh_mode(mode: RefreshTransportMode) -> RefreshTransportMode {
    match mode {
        RefreshTransportMode::TokenBody => RefreshTransportMode::DualCookieTokenBody,
        RefreshTransportMode::DualCookieTokenBody => RefreshTransportMode::TokenBody,
    }
}

fn is_contract_mismatch_auth_error(error: &InkError) -> bool {
    if error.kind != ErrorKind::Auth {
        return false;
    }

    let Some(status) = error_status_code(error) else {
        return false;
    };

    if status != StatusCode::BAD_REQUEST {
        return false;
    }

    let message = error.message.to_ascii_lowercase();
    message.contains("required parameter")
        || message.contains("required parameters")
        || message.contains("please provide")
        || message.contains("missing")
}

fn non_empty_trimmed_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
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
    let response_url = response.url().to_string();
    if status.is_success() {
        if api_debug_verbose_enabled() {
            debug!(
                target: "ink_api::http",
                url = %response_url,
                status = status.as_u16(),
                "api response without body"
            );
        }
        return Ok(());
    }

    let body_text = response.text().unwrap_or_default();
    if api_debug_verbose_enabled() {
        debug!(
            target: "ink_api::http",
            url = %response_url,
            status = status.as_u16(),
            body_bytes = body_text.len(),
            "api error response without expected body payload"
        );
        if api_debug_raw_enabled() {
            debug!(
                target: "ink_api::http",
                url = %response_url,
                status = status.as_u16(),
                raw_body = %truncate_for_error(&body_text, api_debug_max_chars()),
                "api raw error response body"
            );
        }
    }
    Err(parse_error_response(status, &body_text, Some(&headers)))
}

fn parse_json_response<T: DeserializeOwned>(response: Response) -> InkResult<T> {
    let status = response.status();
    let headers = response.headers().clone();
    let response_url = response.url().to_string();
    let body_text = response.text().unwrap_or_default();

    if !status.is_success() {
        if api_debug_verbose_enabled() {
            debug!(
                target: "ink_api::http",
                url = %response_url,
                status = status.as_u16(),
                body_bytes = body_text.len(),
                "api error response"
            );
            if api_debug_raw_enabled() {
                debug!(
                    target: "ink_api::http",
                    url = %response_url,
                    status = status.as_u16(),
                    raw_body = %truncate_for_error(&body_text, api_debug_max_chars()),
                    "api raw error response body"
                );
            }
        }
        return Err(parse_error_response(status, &body_text, Some(&headers)));
    }

    let value = serde_json::from_str::<Value>(&body_text)
        .map_err(|err| InkError::sync(format!("failed to decode API response JSON: {err}")))?;
    let top_keys = collect_object_keys(Some(&value));
    let data = value.get("data");
    let data_keys = collect_object_keys(data);
    let top_retrieved = array_len(value.get("retrieved_items"));
    let data_retrieved = array_len(data.and_then(|inner| inner.get("retrieved_items")));
    let top_saved = array_len(value.get("saved_items"));
    let data_saved = array_len(data.and_then(|inner| inner.get("saved_items")));
    let top_conflicts = array_len(value.get("conflicts"));
    let data_conflicts = array_len(data.and_then(|inner| inner.get("conflicts")));
    let top_sync_token = value.get("sync_token").and_then(Value::as_str);
    let data_sync_token = data
        .and_then(|inner| inner.get("sync_token"))
        .and_then(Value::as_str);
    let top_cursor_token = value.get("cursor_token").and_then(Value::as_str);
    let data_cursor_token = data
        .and_then(|inner| inner.get("cursor_token"))
        .and_then(Value::as_str);

    let mut data_parse_error: Option<String> = None;
    if let Some(data) = value.get("data")
        && !data.is_null()
    {
        match serde_json::from_value::<T>(data.clone()) {
            Ok(parsed) => {
                log_api_json_response(&ApiJsonResponseLogContext {
                    response_url: &response_url,
                    status,
                    body_text: &body_text,
                    top_keys: &top_keys,
                    data_keys: &data_keys,
                    top_retrieved,
                    data_retrieved,
                    top_saved,
                    data_saved,
                    top_conflicts,
                    data_conflicts,
                    top_sync_token,
                    data_sync_token,
                    top_cursor_token,
                    data_cursor_token,
                    parse_path: "data",
                    data_parse_error: None,
                });
                return Ok(parsed);
            }
            Err(err) => {
                data_parse_error = Some(err.to_string());
            }
        }
    }

    match serde_json::from_value::<T>(value.clone()) {
        Ok(parsed) => {
            log_api_json_response(&ApiJsonResponseLogContext {
                response_url: &response_url,
                status,
                body_text: &body_text,
                top_keys: &top_keys,
                data_keys: &data_keys,
                top_retrieved,
                data_retrieved,
                top_saved,
                data_saved,
                top_conflicts,
                data_conflicts,
                top_sync_token,
                data_sync_token,
                top_cursor_token,
                data_cursor_token,
                parse_path: "top-level",
                data_parse_error: data_parse_error.as_deref(),
            });
            Ok(parsed)
        }
        Err(top_level_error) => {
            log_api_json_response(&ApiJsonResponseLogContext {
                response_url: &response_url,
                status,
                body_text: &body_text,
                top_keys: &top_keys,
                data_keys: &data_keys,
                top_retrieved,
                data_retrieved,
                top_saved,
                data_saved,
                top_conflicts,
                data_conflicts,
                top_sync_token,
                data_sync_token,
                top_cursor_token,
                data_cursor_token,
                parse_path: "error",
                data_parse_error: data_parse_error.as_deref(),
            });

            let message = if let Some(data_error) = data_parse_error {
                format!(
                    "failed to map API response to expected shape (data parse failed: {data_error}; top-level parse failed: {top_level_error})"
                )
            } else {
                format!("failed to map API response to expected shape: {top_level_error}")
            };

            Err(InkError::sync(message))
        }
    }
}

fn collect_object_keys(value: Option<&Value>) -> Vec<String> {
    let Some(object) = value.and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut keys: Vec<String> = object.keys().cloned().collect();
    keys.sort_unstable();
    if keys.len() > 16 {
        keys.truncate(16);
        keys.push("...".to_string());
    }
    keys
}

fn array_len(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_array)
        .map(|array| array.len())
        .unwrap_or(0)
}

struct ApiJsonResponseLogContext<'a> {
    response_url: &'a str,
    status: StatusCode,
    body_text: &'a str,
    top_keys: &'a [String],
    data_keys: &'a [String],
    top_retrieved: usize,
    data_retrieved: usize,
    top_saved: usize,
    data_saved: usize,
    top_conflicts: usize,
    data_conflicts: usize,
    top_sync_token: Option<&'a str>,
    data_sync_token: Option<&'a str>,
    top_cursor_token: Option<&'a str>,
    data_cursor_token: Option<&'a str>,
    parse_path: &'a str,
    data_parse_error: Option<&'a str>,
}

fn log_api_json_response(ctx: &ApiJsonResponseLogContext<'_>) {
    if !api_debug_verbose_enabled() {
        return;
    }

    debug!(
        target: "ink_api::http",
        url = %ctx.response_url,
        status = ctx.status.as_u16(),
        body_bytes = ctx.body_text.len(),
        parse_path = ctx.parse_path,
        top_keys = ?ctx.top_keys,
        data_keys = ?ctx.data_keys,
        top_retrieved = ctx.top_retrieved,
        data_retrieved = ctx.data_retrieved,
        top_saved = ctx.top_saved,
        data_saved = ctx.data_saved,
        top_conflicts = ctx.top_conflicts,
        data_conflicts = ctx.data_conflicts,
        top_sync_token_present = ctx.top_sync_token.is_some(),
        data_sync_token_present = ctx.data_sync_token.is_some(),
        top_cursor_token_present = ctx.top_cursor_token.is_some(),
        data_cursor_token_present = ctx.data_cursor_token.is_some(),
        data_parse_error = ctx.data_parse_error.unwrap_or(""),
        "api json response"
    );

    if api_debug_raw_enabled() {
        debug!(
            target: "ink_api::http",
            url = %ctx.response_url,
            status = ctx.status.as_u16(),
            raw_body = %truncate_for_error(ctx.body_text, api_debug_max_chars()),
            "api raw response body"
        );
    }
}

fn api_debug_verbose_enabled() -> bool {
    env_truthy(ENV_API_DEBUG_VERBOSE) || tracing::enabled!(target: "ink_api::http", Level::DEBUG)
}

fn api_debug_raw_enabled() -> bool {
    api_debug_verbose_enabled() && env_truthy(ENV_API_DEBUG_RAW)
}

fn api_debug_max_chars() -> usize {
    env::var(ENV_API_DEBUG_MAX_CHARS)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_API_DEBUG_MAX_CHARS)
}

fn refresh_fallback_enabled() -> bool {
    let Ok(value) = env::var(ENV_API_REFRESH_FALLBACK) else {
        return true;
    };

    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn refresh_retry_attempts() -> usize {
    env::var(ENV_API_REFRESH_RETRY_ATTEMPTS)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.min(6))
        .unwrap_or(DEFAULT_API_REFRESH_RETRY_ATTEMPTS)
}

fn refresh_retry_base_delay_ms() -> u64 {
    env::var(ENV_API_REFRESH_RETRY_BASE_DELAY_MS)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.min(10_000))
        .unwrap_or(DEFAULT_API_REFRESH_RETRY_BASE_DELAY_MS)
}

fn refresh_retry_delay(retry_attempt: usize, error: &InkError) -> Duration {
    if let Some(seconds) = error_retry_after_seconds(error) {
        return Duration::from_secs(seconds.min(30));
    }

    let exponent: u32 = retry_attempt
        .saturating_sub(1)
        .min(6)
        .try_into()
        .unwrap_or(0);
    let multiplier = 1u64 << exponent;
    let backoff_ms = refresh_retry_base_delay_ms()
        .saturating_mul(multiplier)
        .min(10_000);
    Duration::from_millis(backoff_ms)
}

fn is_refresh_retryable_error(error: &InkError) -> bool {
    if error.kind != ErrorKind::Sync {
        return false;
    }

    if error.message.starts_with("network request failed:") {
        return true;
    }

    matches!(
        error_status_code(error),
        Some(
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
    )
}

fn env_truthy(name: &str) -> bool {
    let Ok(value) = env::var(name) else {
        return false;
    };

    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
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

fn error_retry_after_seconds(error: &InkError) -> Option<u64> {
    let marker = "[retry_after_seconds=";
    let start = error.message.find(marker)?;
    let remainder = &error.message[(start + marker.len())..];
    let end = remainder.find(']')?;
    remainder[..end].parse::<u64>().ok()
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
