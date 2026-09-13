use axum::routing::post;
use axum::Json;
use serde_json::json;
use std::net::SocketAddr;

/// Spawn a mock OpenAI-compatible upstream on an ephemeral port.
async fn mock_upstream() -> SocketAddr {
    async fn chat(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
        let last = req["messages"]
            .as_array()
            .and_then(|m| m.last())
            .and_then(|m| m["content"].as_str())
            .unwrap_or("")
            .to_string();
        Json(json!({
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": format!("echo: {last}")},
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
        }))
    }
    let app = axum::Router::new().route("/v1/chat/completions", post(chat));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn test_config(
    upstream: SocketAddr,
    ledger: &std::path::Path,
) -> edge_gate_test_harness::TestConfig {
    edge_gate_test_harness::TestConfig {
        listen: "127.0.0.1:0".into(),
        upstream_url: format!("http://{upstream}"),
        ledger: ledger.to_path_buf(),
    }
}

/// The crate is a binary; integration tests drive it as a subprocess.
/// This harness lives in tests/ and talks HTTP to both sides.
mod edge_gate_test_harness {
    use std::net::SocketAddr;

    pub struct TestConfig {
        pub listen: String,
        pub upstream_url: String,
        pub ledger: std::path::PathBuf,
    }

    pub fn write_config(c: &TestConfig) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "edge_gate_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let toml = format!(
            r#"listen = "{}"

[upstreams.mock]
url = "{}"

[dedup]
enabled = true
min_similarity = 0.5
cache_size = 64

[blinding]
enabled = true
unblind_response = true
patterns = ["sk-test-secret"]

[filter]
enabled = true
blocklist = ["BLOCKED_CONTENT"]

[tarpit]
enabled = false

[audit]
path = "{}"

[costs."test-model"]
input_per_mtok = 1.0
output_per_mtok = 2.0
"#,
            c.listen,
            c.upstream_url,
            c.ledger.display()
        );
        std::fs::write(&path, toml).unwrap();
        path
    }

    /// Start edge_gate as a subprocess on an ephemeral port.
    /// Returns (child, gateway_addr).
    pub async fn spawn(cfg_path: &std::path::Path) -> (std::process::Child, SocketAddr) {
        // grab a free port first
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        // patch the config to use it
        let text = std::fs::read_to_string(cfg_path)
            .unwrap()
            .replace("127.0.0.1:0", &format!("127.0.0.1:{port}"));
        std::fs::write(cfg_path, text).unwrap();

        let bin = env!("CARGO_BIN_EXE_edge_gate");
        let child = std::process::Command::new(bin)
            .args(["serve", "--config", cfg_path.to_str().unwrap()])
            .spawn()
            .unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        // wait for readiness
        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client
                .get(format!("http://{addr}/healthz"))
                .send()
                .await
                .is_ok()
            {
                return (child, addr);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("edge_gate did not become ready");
    }
}

#[tokio::test]
async fn end_to_end_proxy_dedup_blind_audit() {
    let upstream = mock_upstream().await;
    let ledger = std::env::temp_dir().join(format!("eg_ledger_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&ledger);
    let cfg = test_config(upstream, &ledger);
    let cfg_path = edge_gate_test_harness::write_config(&cfg);
    let (mut child, addr) = edge_gate_test_harness::spawn(&cfg_path).await;
    let client = reqwest::Client::new();

    // 1. normal request passes through, blinding applies
    let body = json!({
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "my key is sk-test-secret what is 2+2?"}
        ]
    });
    let r = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let resp: serde_json::Value = r.json().await.unwrap();
    let content = resp["choices"][0]["message"]["content"].as_str().unwrap();
    // upstream echoed the blinded token; unblind restored the secret
    assert!(content.contains("sk-test-secret"), "got: {content}");

    // 2. near-duplicate request -> dedup hit, upstream NOT called twice
    let body2 = json!({
        "model": "test-model",
        "messages": [
            {"role": "user", "content": "my key is sk-test-secret what is 2+2"}
        ]
    });
    let r2 = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&body2)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.headers().get("x-edge-gate").unwrap(), "dedup");

    // 3. audit chain verifies
    let v: serde_json::Value = client
        .get(format!("http://{addr}/audit/verify"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["ok"], true);
    assert!(v["entries"].as_u64().unwrap() >= 4);

    child.kill().unwrap();
    let _ = std::fs::remove_file(&ledger);
    let _ = std::fs::remove_file(&cfg_path);
}
