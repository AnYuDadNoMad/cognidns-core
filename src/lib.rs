//! CogniDNS library entry point.
//! Exposes service modules used by binary and integration tests.
pub mod admin;
pub mod cache;
pub mod codec;
pub mod config;
pub mod context;
pub mod control;
pub mod ctl_cli;
pub mod ctl_config;
pub mod dnssec;
pub mod health;
pub mod ingress;
pub mod logging;
pub mod metrics;
pub mod platform_db;
pub mod policy;
pub mod resolver;
pub mod service;
pub mod topn;
