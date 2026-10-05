# Security

Report vulnerabilities privately to savagetism@icloud.com — do not open
public issues for exploitable weaknesses.

Scope: secret blinding and unblinding correctness, tarpit isolation
between clients, dedup replay semantics, response filter bypass,
audit ledger chain integrity, upstream request routing.

Out of scope: credentials in shapes no pattern covers (see
THREAT_MODEL.md — blind is a floor, not semantic detection), upstream
endpoint trust, and host filesystem access to the ledger file.
