//! `edge_gate` — a local LLM edge gateway.
//!
//! The pipeline stages are usable as a library: [`blind::Blinder`],
//! [`dedup::Deduper`], [`filter::OutputFilter`], [`meter::Meter`],
//! [`tarpit::Tarpit`], [`audit::Audit`]. The binary wraps them in an
//! axum reverse proxy ([`proxy`]).

pub mod audit;
pub mod blind;
pub mod config;
pub mod dedup;
pub mod filter;
pub mod meter;
pub mod proxy;
pub mod tarpit;
