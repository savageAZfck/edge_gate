# Threat model — edge_gate

**Prompt contains a credential.** The blind stage scrubs credential
shapes (builtin regexes + operator literals) before anything leaves the
machine. Upstream sees `⟦EG:…⟧` tokens; unblind restores them only in
the caller's response. A token is keyed on the secret — two different
secrets cannot alias onto one token.

**Secret exfiltration via novel format.** Blind is shape-based, not
semantic — a credential in a shape nobody wrote a pattern for passes
through. The defense is the `custom` list: operators add literal strings
that must never leave. This boundary is stated, not hidden.

**Client floods the gate.** Tarpit delays rather than rejects — no
clean 429 oracle for a flooder to tune against, and per-IP buckets
keep one client from starving the rest.

**Cost of repeated near-identical prompts.** Dedup replays cached
responses on Jaccard similarity; upstream spend for a semantic repeat
is zero. The index is bounded (LRU) so memory cannot grow without limit.

**Upstream response contains secrets.** The filter stage scans the
response against the blocklist — streaming on SSE chunks or buffered —
before it reaches the caller.

**Audit tampering.** The ledger is hash-chained end to end;
`edge_gate verify` recomputes every link offline. A rewritten,
truncated, or reordered file fails verification.

**Honesty of the audit record.** Audit records what the pipeline did —
but redaction is upstream of the audit layer. `data` reaching `record`
is persisted verbatim; a stage that failed to redact writes secrets to
disk. Callers must scrub before recording.

## What this crate guarantees

- Zero-config credential shapes never leave the machine unblinded.
- Operator-configured literals are Aho-Corasick-scrubbed on every
  request, deterministically.
- Blinded tokens restore only on the response path — upstream cannot
  read what it never received.
- The audit ledger detects any single-line edit, deletion, or reorder
  on `verify`.

## What it does not guarantee

- Detection of secrets in shapes no pattern covers — regexes find what
  they are told to find. Blinding is a floor, not a proof of privacy.
- TLS termination or upstream authentication security — the gate
  trusts the configured upstream endpoint; it is not a PKI.
- Protection against a caller with write access to the ledger file
  itself — it detects tampering, it cannot prevent deletion. Chain the
  tip elsewhere (kola, sovereign_ledger) if continuity matters.
- Dedup correctness is a cache semantic, not a semantic guarantee —
  near-identical prompts get near-identical treatment, by design.
