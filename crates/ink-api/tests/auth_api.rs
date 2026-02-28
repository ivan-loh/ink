use httpmock::Method::{GET, POST};
use httpmock::MockServer;
use ink_api::{ItemsSyncRequest, SignInRequest, StandardNotesApi, SyncItemInput};
use ink_core::ErrorKind;
use serde_json::json;

#[test]
fn get_login_params_uses_v2_when_available() {
    let server = MockServer::start();

    let v2 = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(200).json_body(json!({
            "identifier": "user@example.com",
            "pw_cost": 110000,
            "pw_nonce": "nonce",
            "version": "004"
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let result = api
        .get_login_params("user@example.com")
        .expect("login params");

    v2.assert_hits(1);
    assert_eq!(
        result.key_params.identifier.as_deref(),
        Some("user@example.com")
    );
    assert_eq!(result.key_params.version.as_deref(), Some("004"));
    assert!(!result.code_verifier.is_empty());
}

#[test]
fn get_login_params_falls_back_to_v1_when_v2_missing() {
    let server = MockServer::start();

    let v2 = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(404).json_body(json!({"message": "not found"}));
    });

    let v1 = server.mock(|when, then| {
        when.method(POST).path("/v1/login-params");
        then.status(200).json_body(json!({
            "identifier": "fallback@example.com",
            "pw_cost": 100000,
            "pw_nonce": "fallback-nonce",
            "version": "004"
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let result = api
        .get_login_params("fallback@example.com")
        .expect("fallback login params");

    v2.assert_hits(1);
    v1.assert_hits(1);
    assert_eq!(
        result.key_params.identifier.as_deref(),
        Some("fallback@example.com")
    );
}

#[test]
fn sign_in_returns_session_payload() {
    let server = MockServer::start();

    let sign_in = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .header("x-snjs-version", "ink/0.1");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "access_expiration": 2000000000,
                "refresh_expiration": 2000001000,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            },
            "key_params": {
                "identifier": "user@example.com",
                "version": "004"
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .sign_in(&SignInRequest {
            email: "user@example.com".to_string(),
            server_password: "password".to_string(),
            code_verifier: "code-verifier".to_string(),
            ephemeral: false,
        })
        .expect("sign in response");

    sign_in.assert_hits(1);
    let session = response.session.expect("session");
    assert_eq!(session.access_token, "access-token");
    assert_eq!(response.user.expect("user").email, "user@example.com");
}

#[test]
fn sign_in_sends_special_character_password_verbatim_in_json() {
    let server = MockServer::start();
    let password = r#"p@ss"word\with/slash+=:#?$&"#;

    let sign_in = server.mock(|when, then| {
        when.method(POST)
            .path("/v2/login")
            .header("x-snjs-version", "ink/0.1")
            .json_body(json!({
                "api": "20240226",
                "email": "user@example.com",
                "password": password,
                "ephemeral": false,
                "code_verifier": "code-verifier"
            }));
        then.status(200).json_body(json!({
            "session": {
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "access_expiration": 2000000000,
                "refresh_expiration": 2000001000,
                "readonly_access": false
            },
            "user": {
                "uuid": "user-uuid",
                "email": "user@example.com"
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let _ = api
        .sign_in(&SignInRequest {
            email: "user@example.com".to_string(),
            server_password: password.to_string(),
            code_verifier: "code-verifier".to_string(),
            ephemeral: false,
        })
        .expect("sign in response");

    sign_in.assert_hits(1);
}

#[test]
fn sign_in_extracts_cookie_headers() {
    let server = MockServer::start();

    let sign_in = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(200)
            .header("set-cookie", "access_token_abc=one; Path=/; HttpOnly")
            .header("set-cookie", "refresh_token_abc=one; Path=/; HttpOnly")
            .json_body(json!({
                "session": {
                    "access_token": "2:access-token",
                    "refresh_token": "2:refresh-token",
                    "access_expiration": 2000000000,
                    "refresh_expiration": 2000001000,
                    "readonly_access": false
                }
            }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .sign_in(&SignInRequest {
            email: "user@example.com".to_string(),
            server_password: "password".to_string(),
            code_verifier: "code-verifier".to_string(),
            ephemeral: false,
        })
        .expect("sign in response");

    sign_in.assert_hits(1);
    assert_eq!(
        response.access_token_cookie.as_deref(),
        Some("access_token_abc=one")
    );
    assert_eq!(
        response.refresh_token_cookie.as_deref(),
        Some("refresh_token_abc=one")
    );
}

#[test]
fn refresh_session_returns_updated_session() {
    let server = MockServer::start();

    let refresh = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/sessions/refresh")
            .header("x-snjs-version", "ink/0.1");
        then.status(200).json_body(json!({
            "session": {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "access_expiration": 2000002000,
                "refresh_expiration": 2000003000,
                "readonly_access": false
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .refresh_session("old-access", "old-refresh", None)
        .expect("refresh response");

    refresh.assert_hits(1);
    let session = response.session.expect("session");
    assert_eq!(session.access_token, "new-access");
    assert_eq!(session.refresh_token, "new-refresh");
}

#[test]
fn refresh_session_extracts_cookie_headers() {
    let server = MockServer::start();

    let refresh = server.mock(|when, then| {
        when.method(POST).path("/v1/sessions/refresh");
        then.status(200)
            .header("set-cookie", "access_token_new=two; Path=/; HttpOnly")
            .header("set-cookie", "refresh_token_new=two; Path=/; HttpOnly")
            .json_body(json!({
                "session": {
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "access_expiration": 2000002000,
                    "refresh_expiration": 2000003000,
                    "readonly_access": false
                }
            }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .refresh_session("old-access", "old-refresh", None)
        .expect("refresh response");

    refresh.assert_hits(1);
    assert_eq!(
        response.access_token_cookie.as_deref(),
        Some("access_token_new=two")
    );
    assert_eq!(
        response.refresh_token_cookie.as_deref(),
        Some("refresh_token_new=two")
    );
}

#[test]
fn refresh_session_uses_cookie_flow_for_v2_tokens() {
    let server = MockServer::start();

    let refresh = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/sessions/refresh")
            .header("authorization", "Bearer 2:refresh-token")
            .header("cookie", "refresh_token_abc=xyz")
            .json_body(json!({
                "api": "20240226"
            }));
        then.status(200).json_body(json!({
            "session": {
                "access_token": "2:new-access",
                "refresh_token": "2:new-refresh",
                "access_expiration": 2000002000,
                "refresh_expiration": 2000003000,
                "readonly_access": false
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .refresh_session(
            "2:access-token",
            "2:refresh-token",
            Some("refresh_token_abc=xyz"),
        )
        .expect("refresh response");

    refresh.assert_hits(1);
    let session = response.session.expect("session");
    assert_eq!(session.access_token, "2:new-access");
    assert_eq!(session.refresh_token, "2:new-refresh");
}

#[test]
fn refresh_session_cookie_flow_requires_cookie() {
    let server = MockServer::start();
    let api = StandardNotesApi::new(&server.base_url()).expect("api client");

    let error = api
        .refresh_session("2:access-token", "2:refresh-token", None)
        .expect_err("should fail");

    assert_eq!(error.kind, ErrorKind::Auth);
    assert!(error.message.contains("refresh token cookie missing"));
}

#[test]
fn sign_out_sends_bearer_authorization_header() {
    let server = MockServer::start();

    let logout = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/logout")
            .header("authorization", "Bearer access-token");
        then.status(200).json_body(json!({"success": true}));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    api.sign_out("access-token").expect("logout");

    logout.assert_hits(1);
}

#[test]
fn sign_in_unauthorized_maps_to_auth_error() {
    let server = MockServer::start();

    let sign_in = server.mock(|when, then| {
        when.method(POST).path("/v2/login");
        then.status(401).json_body(json!({
            "meta": {"auth": {}},
            "data": {
                "error": {
                    "message": "Invalid email or password"
                }
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let error = api
        .sign_in(&SignInRequest {
            email: "user@example.com".to_string(),
            server_password: "bad-password".to_string(),
            code_verifier: "code-verifier".to_string(),
            ephemeral: false,
        })
        .expect_err("should fail");

    sign_in.assert_hits(1);
    assert_eq!(error.kind, ErrorKind::Auth);
    assert!(error.message.contains("http_status=401"));
}

#[test]
fn get_login_params_uses_v1_get_fallback() {
    let server = MockServer::start();

    let v2 = server.mock(|when, then| {
        when.method(POST).path("/v2/login-params");
        then.status(404);
    });

    let v1_post = server.mock(|when, then| {
        when.method(POST).path("/v1/login-params");
        then.status(405);
    });

    let v1_get = server.mock(|when, then| {
        when.method(GET)
            .path("/v1/login-params")
            .query_param("email", "legacy@example.com");
        then.status(200).json_body(json!({
            "identifier": "legacy@example.com",
            "version": "004"
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .get_login_params("legacy@example.com")
        .expect("legacy login params");

    v2.assert_hits(1);
    v1_post.assert_hits(1);
    v1_get.assert_hits(1);
    assert_eq!(
        response.key_params.identifier.as_deref(),
        Some("legacy@example.com")
    );
}

#[test]
fn sync_items_sends_authorization_cookie_and_tokens() {
    let server = MockServer::start();

    let sync = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer 2:access-token")
            .header("cookie", "access_token_abc=xyz")
            .json_body(json!({
                "api": "20240226",
                "items": [{
                    "uuid": "item-1",
                    "content_type": "Note",
                    "content": "004:content",
                    "enc_item_key": "004:key",
                    "items_key_id": "items-key-1",
                    "deleted": false
                }],
                "sync_token": "sync-1",
                "limit": 100
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [{
                    "uuid": "item-1",
                    "content_type": "Note",
                    "content": "004:content",
                    "enc_item_key": "004:key",
                    "items_key_id": "items-key-1",
                    "deleted": false
                }],
                "conflicts": [],
                "sync_token": "sync-2"
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .sync_items(
            "2:access-token",
            Some("access_token_abc=xyz"),
            &ItemsSyncRequest {
                items: vec![SyncItemInput {
                    uuid: "item-1".to_string(),
                    content_type: "Note".to_string(),
                    content: "004:content".to_string(),
                    enc_item_key: "004:key".to_string(),
                    items_key_id: Some("items-key-1".to_string()),
                    deleted: Some(false),
                    ..SyncItemInput::default()
                }],
                limit: Some(100),
                sync_token: Some("sync-1".to_string()),
                cursor_token: None,
            },
        )
        .expect("sync response");

    sync.assert_hits(1);
    assert_eq!(response.sync_token.as_deref(), Some("sync-2"));
    assert_eq!(response.saved_items.len(), 1);
}

#[test]
fn sync_items_requires_cookie_for_v2_access_tokens() {
    let server = MockServer::start();
    let api = StandardNotesApi::new(&server.base_url()).expect("api client");

    let error = api
        .sync_items(
            "2:access-token",
            None,
            &ItemsSyncRequest {
                items: Vec::new(),
                limit: None,
                sync_token: None,
                cursor_token: None,
            },
        )
        .expect_err("should fail");

    assert_eq!(error.kind, ErrorKind::Auth);
    assert!(error.message.contains("access token cookie missing"));
}

#[test]
fn sync_items_supports_cursor_token_paging_request_fields() {
    let server = MockServer::start();

    let sync = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token")
            .json_body(json!({
                "api": "20240226",
                "items": [],
                "sync_token": "sync-1",
                "cursor_token": "cursor-1",
                "limit": 75
            }));
        then.status(200).json_body(json!({
            "data": {
                "retrieved_items": [],
                "saved_items": [],
                "conflicts": [],
                "sync_token": "sync-2",
                "cursor_token": "cursor-2"
            }
        }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let response = api
        .sync_items(
            "access-token",
            None,
            &ItemsSyncRequest {
                items: Vec::new(),
                limit: Some(75),
                sync_token: Some("sync-1".to_string()),
                cursor_token: Some("cursor-1".to_string()),
            },
        )
        .expect("sync response");

    sync.assert_hits(1);
    assert_eq!(response.sync_token.as_deref(), Some("sync-2"));
    assert_eq!(response.cursor_token.as_deref(), Some("cursor-2"));
}

#[test]
fn sync_items_rate_limit_includes_retry_after_marker() {
    let server = MockServer::start();

    let sync = server.mock(|when, then| {
        when.method(POST)
            .path("/v1/items")
            .header("authorization", "Bearer access-token");
        then.status(429)
            .header("retry-after", "7")
            .json_body(json!({
                "error": {
                    "message": "Too many requests"
                }
            }));
    });

    let api = StandardNotesApi::new(&server.base_url()).expect("api client");
    let error = api
        .sync_items(
            "access-token",
            None,
            &ItemsSyncRequest {
                items: Vec::new(),
                limit: None,
                sync_token: None,
                cursor_token: None,
            },
        )
        .expect_err("sync should fail");

    sync.assert_hits(1);
    assert_eq!(error.kind, ErrorKind::Sync);
    assert!(error.message.contains("http_status=429"));
    assert!(error.message.contains("retry_after_seconds=7"));
}
