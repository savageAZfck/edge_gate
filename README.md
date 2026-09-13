# edge_gate

A local LLM edge gateway. One Rust binary that sits between your apps
and any OpenAI-compatible endpoint, and does five things to every
request before it leaves your machine — and every response on the way
back.

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

| Stage | Mechanism | Deterministic? |
|---|---|---|
| tarpit | per-IP token bucket, adds delay instead of errors | yes |
| blind | literal-substring Aho-Corasick → keyed `⟦EG:hash⟧` tokens; response unblinds | yes |
| dedup | word unigram+bigram feature sets, Jaccard ≥ `min_similarity` | yes |
| filter | Aho-Corasick blocklist; SSE streams are cut mid-flight | yes |
| meter | upstream `usage` when present, chars/4 estimate otherwise | yes |
| audit | `{ts,type,data,prev_hash,hash}` SHA-256 chain, append-only | verifiable |

## Verify the audit trail

```sh
edge_gate verify --ledger edge_gate_ledger.jsonl
# → "412 entries verified, chain intact"
# or "CHAIN BROKEN at line 207" + exit 1
```

Or live: `GET /audit/verify`. Metrics: `GET /metrics` (Prometheus
exposition, including `edge_gate_dedup_saved_usd`).

## Honest scope

- **Blinding is literal-substring, not NER.** Put your actual secrets,
  key formats, and sensitive phrases in `blinding.patterns` (or
  `patterns_file`). It will not find a secret it wasn't told about.
- **Dedup is lexical similarity, not meaning.** "2+2?" and "two plus
  two" don't dedup; paraphrases sharing ~60% of word features do.
  Tune `min_similarity`.
- **Streaming filter** scans accumulated text and cuts the stream on a
  hit — a pattern split across chunk boundaries is caught once the
  second half lands, so partial text may have already flowed.
- **The chain detects tampering; it doesn't prevent it.** An attacker
  who rewrites the file AND recomputes the chain defeats it — seal the
  ledger elsewhere (e.g. periodic external checkpointing) if you need
  stronger guarantees.
- HTTP/1.1 OpenAI-style JSON is the tested surface. Anthropic-shaped
  bodies pass through but usage/meter parsing expects `prompt_tokens`
  / `input_tokens` conventions.

## Tests

```sh
cargo test
```

10 unit tests (blinding round-trip, dedup similarity, tarpit buckets,
audit tamper detection) + 1 integration test that spawns the real
gateway against a mock upstream and exercises proxy → blind → dedup →
unblind → audit verify end to end.
