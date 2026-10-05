# SPEC — edge_gate (local LLM edge gateway)

## Pipeline

Every request passes seven stages before leaving the machine; every
response passes the remainder on the way back:

```
app → edge_gate → upstream
       tarpit → blind → dedup → forward → filter → unblind → meter → audit
```

Pipeline overhead ~30 µs per request; upstream latency is seconds.

## tarpit

Per-client-IP token bucket (`rps`, `burst`, `delay_ms`). Requests over
the limit are *delayed*, not rejected — floods throttle without a clean
429 signal to hammer against. Tarpitted count is exported to metrics.

## blind

Two detectors run over request text before forwarding:

- `builtin` — regexes for common credential shapes (OpenAI/Anthropic
  keys, AWS AKIA/ASIA, GitHub tokens, Slack tokens, JWTs, PEM blocks).
  Works at zero config.
- `custom` — Aho-Corasick over operator-configured literal strings
  (project names, internal hostnames).

Matches are replaced with `⟦EG:xxxxxxxxxxxx⟧` — hex keyed on the secret,
so identical secrets blind identically (dedup stays intact) and distinct
secrets never collide. The token→secret map is populated lazily per
`blind()` call.

## unblind

On the response path, `⟦EG:…⟧` tokens the model echoed are restored to
the original secret — the upstream never saw it; the caller does.

## dedup

Semantic dedup: hashed word-feature Jaccard similarity over normalized
prompt text. Two prompts at or above `min_similarity` are the same
request and the cached response replays — the upstream is never hit.
LRU-bounded index, FxHash-keyed tallies.

## forward

OpenAI-compatible `POST /v1/*` passthrough, SSE-aware. Named upstreams
route on `/<name>/v1/...`; per-upstream `url`, `api_key`, timeout.

## filter

Blocklist scan on the response — streaming (incremental, on SSE chunks)
or buffered. Matches replace the response with a firewall notice.

## meter

Per-model token and USD accounting; Prometheus exposition on
`/metrics`.

## audit

Append-only hash-chained JSONL:

```json
{"ts":0,"type":"...","data":{...},"prev_hash":"...","hash":"..."}
```

`hash = sha256(ts|type|data|prev_hash)` over the canonical tuple;
genesis `prev_hash` is 64 zeroes. `edge_gate verify` walks the file and
recomputes — truncation, rewrite, or reorder all break the chain. Data
must reach the audit layer already redacted; the ledger records what it
is given.
