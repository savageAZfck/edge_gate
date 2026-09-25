# edge_gate

[![CI](https://github.com/savageAZfck/edge_gate/actions/workflows/ci.yml/badge.svg)](https://github.com/savageAZfck/edge_gate/actions/workflows/ci.yml)

A local LLM edge gateway. One Rust binary that sits between your apps
and any OpenAI-compatible endpoint, and does seven things to every
request before it leaves your machine — and every response on the way
back. Total pipeline overhead: **~30 µs per request** (measured, see
[benchmarks](#benchmarks)) — against upstream latency measured in
seconds, the gate is effectively free.

```
app → edge_gate → upstream API
       │
       ├─ tarpit      per-IP token bucket; floods get delayed, not 429s
       ├─ blind       Aho-Corasick scrub of secrets/PII → ⟦EG:…⟧ tokens
       ├─ dedup       Jaccard feature-set similarity → replay cached answer
       ├─ forward     OpenAI-compatible POST /v1/* passthrough (SSE-aware)
       ├─ filter      blocklist scan on the response (streaming or buffered)
       ├─ unblind     secrets the model echoed get restored for your eyes only
       ├─ meter       per-model token + USD accounting (Prometheus /metrics)
       └─ audit       every event appended to a hash-chained JSONL ledger
```

## Why

LLM gateways exist — LiteLLM, Portkey, Kong. They're control-plane
products written in Python/Go, built for platforms teams. edge_gate is
the opposite posture: **local-first, single binary, deterministic, and
everything it does is provable** — the audit ledger is a SHA-256 hash
chain that any third party can verify offline with `edge_gate verify`.
No databases, no dashboard, no cloud.

## Install / run

```sh
cargo build --release
cp edge_gate.toml my_gate.toml    # edit upstreams, patterns, costs
./target/release/edge_gate serve --config my_gate.toml
```

Point anything OpenAI-compatible at it:

```sh
curl http://127.0.0.1:8400/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"what is 2+2?"}]}'
```

Named upstreams: `POST http://127.0.0.1:8400/<name>/v1/chat/completions`
— e.g. `local` → Ollama, `openai` → api.openai.com — one port, one
audit trail.

## What each stage actually does

| Stage | Mechanism | Cost |
|---|---|---|
| tarpit | per-IP token bucket, adds delay instead of errors | ~0 (only on overage) |
| blind | built-in credential regexes (OpenAI/AWS/GitHub/Slack/Google/JWT/PEM/Bearer keys) + literal Aho-Corasick → keyed `⟦EG:hash⟧` tokens; echoed secrets unblinded | ~4.3 µs |
| dedup | word unigram+bigram feature sets, Jaccard ≥ `min_similarity`, inverted index | ~24 µs |
| filter | Aho-Corasick blocklist; SSE streams are cut mid-flight | ~10 ns |
| meter | upstream `usage` when present, chars/4 estimate otherwise | negligible |
| audit | `{ts,type,data,prev_hash,hash}` SHA-256 chain, append-only | ~µs append |

Blinding works **at zero config** — the built-in regex set catches
common credential shapes out of the box; `blinding.patterns` adds your
literal strings (project names, internal hostnames) on top.

## Verify the audit trail

```sh
edge_gate verify --ledger edge_gate_ledger.jsonl
# → "412 entries verified, chain intact"
# or "CHAIN BROKEN at line 207" + exit 1
```

**Signed checkpoints** — pin the tip under an ed25519 key, then prove
later that history back to that point is unchanged:

```sh
edge_gate keygen                            # one-time keypair
echo <secret> > ~/edge_gate.key && chmod 600 ~/edge_gate.key
edge_gate checkpoint --key-file ~/edge_gate.key --out cp.json
cp cp.json /elsewhere/                      # store the proof off-box
edge_gate verify --checkpoint cp.json
# → "checkpoint tip present — history back to checkpoint intact"
```

Unsigned checkpoints still work (`checkpoint` without `--key-file`);
signed ones survive an attacker who can rewrite both the ledger and
the checkpoint file.

Or live: `GET /audit/verify`. Metrics: `GET /metrics` (Prometheus
exposition, including `edge_gate_dedup_saved_usd`).

## Benchmarks

`cargo bench` — criterion, this machine (Apple Silicon):

| stage | time |
|---|---|
| blind request body (regex + Aho-Corasick) | ~4.3 µs |
| feature_set (prompt fingerprint) | ~1.2 µs |
| dedup lookup, mixed cache (1024) | ~24 µs |
| dedup lookup, adversarial shared-vocab cache (1024) | ~50 µs |
| filter response | ~10 ns |

Full pipeline ≈ **30 µs** added per request, ~50 µs worst case — vs.
upstream latency measured in seconds. Dedup uses an inverted index
(feature → entries) so only entries sharing ≥1 feature are scored; the
adversarial column shows the degenerate case where *every* cached
prompt shares vocabulary, which is the true scaling ceiling.

## Honest scope

- **Blinding is pattern-based, not NER.** The built-in regexes catch
  credential *shapes*; `blinding.patterns` catches your literal
  strings. A secret matching neither still passes through — blinding
  is a floor, not a guarantee.
- **Dedup is lexical similarity, not meaning.** "2+2?" and "two plus
  two" don't dedup; paraphrases sharing ~60% of word features do.
  Tune `min_similarity`.
- **Streams are buffered, not chunked through.** `stream: true`
  requests are accumulated upstream, filtered, cached, then delivered
  as one SSE body — so nothing filtered ever reaches the client, and
  dedup can replay streams, but the client sees no incremental tokens
  (TTFT ≈ full upstream latency). Making it stream *and* filter
  incrementally is the known tradeoff to revisit.
- **The chain detects tampering; it doesn't prevent it.** An attacker
  who rewrites the file AND recomputes the chain defeats it — seal the
  ledger elsewhere (e.g. periodic external checkpointing) if you need
  stronger guarantees.
- HTTP/1.1 OpenAI-style JSON is the tested surface. Anthropic-shaped
  bodies pass through but usage/meter parsing expects `prompt_tokens`
  / `input_tokens` conventions.
- Dedup's inverted index bounds lookups to feature-sharing entries;
  ~24µs typical, ~50µs when every cached prompt shares vocabulary.
  That's the scaling ceiling to know about.

## Library use

The stages are a library too — `use edge_gate::blind::Blinder` etc. —
if you want the pipeline without the proxy.

## Tests

```sh
cargo test && cargo bench
```

14 unit tests (blinding round-trip + builtin credential detection,
dedup similarity, tarpit buckets, audit tamper detection) + 1
integration test that spawns the real gateway against a mock upstream
and exercises proxy → blind → dedup → unblind → audit verify end to
end. CI runs fmt/clippy/test on every push.

## License

MIT License — (c) 2026 Adam Clark. See [LICENSE](LICENSE).
Contact savagetism@icloud.com for collaboration or partnership.
