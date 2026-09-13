use crate::audit::Audit;
use crate::blind::Blinder;
use crate::config::Config;
use crate::dedup::{prompt_text, Deduper};
use crate::filter::{OutputFilter, REFUSAL};
use crate::meter::Meter;
use crate::tarpit::Tarpit;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde_json::json;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct AppState {
    pub cfg: Config,
    pub client: reqwest::Client,
    pub blinder: Blinder,
    pub deduper: Option<Deduper>,
    pub filter: Arc<OutputFilter>,
    pub meter: Meter,
    pub tarpit: Option<Tarpit>,
    pub audit: Audit,
    pub default_upstream: String,
}

pub fn router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/healthz", axum::routing::get(healthz))
        .route("/metrics", axum::routing::get(metrics))
        .route("/audit/verify", axum::routing::get(audit_verify))
        .route("/v1/*path", axum::routing::post(forward).get(forward_get))
        .route(
            "/{upstream}/v1/*path",
            axum::routing::post(forward_named).get(forward_get_named),
        )
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(s): State<Arc<AppState>>) -> String {
    let mut out = s.meter.render();
    if let Some(t) = &s.tarpit {
        out.push_str(&format!(
            "edge_gate_tarpitted_total {}\n",
            t.tarpitted_count()
        ));
    }
    if let Some(d) = &s.deduper {
        let (h, m, n) = d.stats();
        out.push_str(&format!(
            "edge_gate_dedup_hits_total {h}\nedge_gate_dedup_misses_total {m}\nedge_gate_dedup_cache_entries {n}\n"
        ));
    }
    out
}

async fn audit_verify(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    match crate::audit::verify(s.audit.path()) {
        Ok((n, bad)) => {
            axum::Json(json!({"entries": n, "first_bad_line": bad, "ok": bad.is_none()}))
        }
        Err(e) => axum::Json(json!({"error": e.to_string()})),
    }
}

/// GET passthrough (e.g. /v1/models): no blinding/dedup — read-only
/// upstream fetch with the same upstream-selection rules.
async fn forward_get(
    State(s): State<Arc<AppState>>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    get_inner(s, headers, path, None).await
}

async fn forward_get_named(
    State(s): State<Arc<AppState>>,
    Path((upstream, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    get_inner(s, headers, path, Some(upstream)).await
}

async fn get_inner(
    s: Arc<AppState>,
    headers: HeaderMap,
    path: String,
    named: Option<String>,
) -> Response {
    let upstream_name = named.unwrap_or_else(|| s.default_upstream.clone());
    let Some(upstream) = s.cfg.upstreams.get(&upstream_name) else {
        return err(
            StatusCode::BAD_GATEWAY,
            &format!("unknown upstream '{upstream_name}'"),
        );
    };
    let url = format!("{}/v1/{}", upstream.url.trim_end_matches('/'), path);
    let mut req = s.client.get(&url).timeout(std::time::Duration::from_millis(
        upstream.timeout_ms.unwrap_or(120_000),
    ));
    if let Some(key) = &upstream.api_key {
        req = req.bearer_auth(key);
    } else if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        req = req.header("authorization", auth);
    }
    match req.send().await {
        Ok(r) => {
            let status = r.status();
            let body = r.bytes().await.unwrap_or_default();
            (
                StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
                [("content-type", "application/json")],
                body,
            )
                .into_response()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, &format!("upstream: {e}")),
    }
}

async fn forward_named(
    state: State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (upstream, path) = path.0;
    forward_inner(state.0, conn, headers, body, path, Some(upstream)).await
}

async fn forward(
    state: State<Arc<AppState>>,
    conn: ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    forward_inner(state.0, conn, headers, body, path, None).await
}

async fn forward_inner(
    s: Arc<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
    path: String,
    named: Option<String>,
) -> Response {
    // 1. tarpit
    if let Some(t) = &s.tarpit {
        let delay = t.check(addr.ip());
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    let upstream_name = named.unwrap_or_else(|| s.default_upstream.clone());
    let Some(upstream) = s.cfg.upstreams.get(&upstream_name) else {
        return err(
            StatusCode::BAD_GATEWAY,
            &format!("unknown upstream '{upstream_name}'"),
        );
    };

    // 2. parse + blind
    let text = String::from_utf8_lossy(&body).to_string();
    let mut blinded_hits = 0usize;
    let outbound = if s.cfg.blinding.enabled && s.blinder.is_active() {
        let (b, n) = s.blinder.blind(&text);
        blinded_hits = n;
        b
    } else {
        text.clone()
    };

    let parsed: Option<serde_json::Value> = serde_json::from_str(&outbound).ok();
    let is_stream = parsed
        .as_ref()
        .and_then(|p| p.get("stream"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let model = parsed
        .as_ref()
        .and_then(|p| p.get("model"))
        .and_then(|m| m.as_str())
        .unwrap_or("unknown")
        .to_string();
    let fingerprint = parsed.as_ref().map(prompt_text).unwrap_or_default();

    // 3. dedup (any parseable request — streams replay cached SSE)
    if parsed.is_some() {
        if let Some(d) = &s.deduper {
            if let Some(cached) = d.get(&fingerprint) {
                s.meter.record_dedup_save(&model);
                s.audit.record(
                    "dedup_hit",
                    json!({"path": path, "model": model, "upstream": upstream_name, "stream": is_stream}),
                );
                if let Some(sse) = cached.get("_edge_gate_sse").and_then(|v| v.as_str()) {
                    return Response::builder()
                        .status(200)
                        .header("content-type", "text/event-stream")
                        .header("cache-control", "no-cache")
                        .header("x-edge-gate", "dedup")
                        .body(axum::body::Body::from(sse.to_string()))
                        .unwrap_or_else(|_| {
                            (StatusCode::INTERNAL_SERVER_ERROR, "replay failed").into_response()
                        });
                }
                return (
                    StatusCode::OK,
                    [
                        ("content-type", "application/json"),
                        ("x-edge-gate", "dedup"),
                    ],
                    serde_json::to_string(&*cached).unwrap_or_default(),
                )
                    .into_response();
            }
        }
    }

    // 4. forward upstream
    let url = format!("{}/v1/{}", upstream.url.trim_end_matches('/'), path);
    let mut req = s
        .client
        .post(&url)
        .header("content-type", "application/json")
        .timeout(std::time::Duration::from_millis(
            upstream.timeout_ms.unwrap_or(120_000),
        ))
        .body(outbound.clone());
    for (k, v) in headers.iter() {
        let name = k.as_str();
        if matches!(
            name,
            "host" | "content-length" | "authorization" | "connection"
        ) {
            continue;
        }
        if let Ok(val) = v.to_str() {
            req = req.header(name, val);
        }
    }
    if let Some(key) = &upstream.api_key {
        req = req.bearer_auth(key);
    } else if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        req = req.header("authorization", auth);
    }

    let upstream_resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            s.audit.record(
                "upstream_error",
                json!({"path": path, "upstream": upstream_name, "error": e.to_string()}),
            );
            return err(StatusCode::BAD_GATEWAY, &format!("upstream: {e}"));
        }
    };
    let status = upstream_resp.status();

    s.audit.record(
        "request",
        json!({
            "path": path, "model": model, "upstream": upstream_name,
            "blinded": blinded_hits, "stream": is_stream,
            "body_sha256": s.cfg.audit.record_bodies.then(|| {
                let mut h = sha2::Sha256::new();
                sha2::Digest::update(&mut h, outbound.as_bytes());
                hex::encode(h.finalize())
            }),
        }),
    );

    if is_stream {
        return stream_response(s, upstream_resp, status, fingerprint, model, path).await;
    }

    // 5. buffered response path
    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => return err(StatusCode::BAD_GATEWAY, &format!("upstream body: {e}")),
    };
    let mut resp_text = String::from_utf8_lossy(&resp_bytes).to_string();

    // 6. output filter
    if s.filter.is_active() && s.filter.check(&resp_text) {
        s.audit.record(
            "filter_block",
            json!({"path": path, "model": model, "upstream": upstream_name}),
        );
        return (StatusCode::OK, REFUSAL).into_response();
    }

    // 7. unblind secrets the upstream echoed
    if s.cfg.blinding.unblind_response && s.blinder.is_active() {
        resp_text = s.blinder.unblind(&resp_text);
    }

    // 8. meter + cache + audit
    let usage = serde_json::from_str::<serde_json::Value>(&resp_text)
        .ok()
        .and_then(|v| v.get("usage").cloned());
    let usd = s.meter.record(&model, usage.as_ref(), outbound.len());
    if status.is_success() {
        if let (Some(d), true) = (&s.deduper, parsed.is_some()) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp_text) {
                d.put(&fingerprint, v);
            }
        }
    }
    s.audit.record(
        "response",
        json!({
            "path": path, "model": model, "status": status.as_u16(),
            "usd": usd, "filtered": false,
        }),
    );

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        [("content-type", "application/json")],
        resp_text,
    )
        .into_response()
}

/// SSE passthrough with incremental filtering: the upstream body is
/// buffered while scanned; on a blocklist hit the stream is replaced by
/// a refusal event instead of the remaining upstream bytes. Completed
/// clean streams are cached so dedup can replay them.
async fn stream_response(
    s: Arc<AppState>,
    upstream_resp: reqwest::Response,
    status: StatusCode,
    fingerprint: String,
    model: String,
    path: String,
) -> Response {
    let filter = s.filter.clone();
    let filter_active = filter.is_active();
    let mut stream = upstream_resp.bytes_stream();
    let mut accumulated = String::new();
    let mut blocked = false;

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                accumulated.push_str(&String::from_utf8_lossy(&bytes));
                if filter_active && filter.check(&accumulated) {
                    blocked = true;
                    accumulated = format!("data: {}\n\n", REFUSAL);
                    s.audit.record(
                        "filter_block",
                        json!({"path": path, "model": model, "stream": true}),
                    );
                    break;
                }
            }
            Err(e) => {
                accumulated.push_str(&format!("data: {{\"error\":\"upstream stream: {e}\"}}\n\n"));
                break;
            }
        }
    }

    if status.is_success() && !blocked && !fingerprint.is_empty() {
        if let Some(d) = &s.deduper {
            d.put(&fingerprint, json!({"_edge_gate_sse": accumulated}));
        }
    }
    // metering is best-effort for streams: OpenAI only sends usage with
    // stream_options.include_usage, so estimate from buffered size.
    s.meter.record(&model, None, accumulated.len());
    s.audit.record(
        "response",
        json!({
            "path": path, "model": model, "status": status.as_u16(),
            "stream": true, "filtered": blocked,
        }),
    );

    Response::builder()
        .status(status)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .body(axum::body::Body::from(accumulated))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "stream build failed").into_response()
        })
}

fn err(status: StatusCode, msg: &str) -> Response {
    (
        status,
        axum::Json(json!({"error": {"message": msg, "type": "edge_gate_error"}})),
    )
        .into_response()
}
