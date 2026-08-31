//! IP allowlist ToolGate plugin for MCPG.
//!
//! Denies requests whose client IP is not in the configured CIDR
//! allowlist. Client IP is extracted from request headers
//! (X-Forwarded-For, X-Real-IP) or falls back to the direct peer
//! address propagated by the transport.
//!
//! Distributed as a `native-cdylib-v1` plugin.

use ipnet::IpNet;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{GateDecision, PluginClass, PluginContext, PluginManifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::declare_plugin;
use mcpg_plugin_sdk::ffi::SyncToolGate;
use serde::Deserialize;
use std::net::IpAddr;
use std::sync::OnceLock;

const PLUGIN_ID: &str = "dev.mcpg.ip-allowlist";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpAllowlistConfig {
    /// CIDR ranges to allow (e.g. `["10.0.0.0/8", "192.168.1.0/24", "::1/128"]`).
    pub allow: Vec<String>,
    /// Header to extract client IP from (default: `x-forwarded-for`).
    #[serde(default = "default_ip_header")]
    pub ip_header: String,
    /// Optional per-tool overrides. If empty, all tools are gated.
    #[serde(default)]
    pub tools: Vec<String>,
}

fn default_ip_header() -> String {
    "x-forwarded-for".into()
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/// CIDR-based IP allowlist gate that denies requests from non-listed IPs.
pub struct IpAllowlistPlugin {
    manifest: PluginManifest,
    networks: Vec<IpNet>,
    ip_header: String,
    tool_patterns: Vec<String>,
    /// Unified host-observability handle. See the rate-limit
    /// plugin's matching field for the design notes — same install
    /// path (factory closure), same short-circuit when the slot is
    /// empty (test paths), same coexistence with the internal
    /// `tracing::*` + `metrics::*` calls.
    host_handle: OnceLock<HostHandle>,
}

impl IpAllowlistPlugin {
    pub fn from_config(config_value: &serde_json::Value) -> Result<Self, String> {
        let config: IpAllowlistConfig =
            serde_json::from_value(config_value.clone()).map_err(|e| format!("{e}"))?;
        let mut networks = Vec::with_capacity(config.allow.len());
        for cidr in &config.allow {
            let net: IpNet = cidr
                .parse()
                .map_err(|e| format!("invalid CIDR '{cidr}': {e}"))?;
            networks.push(net);
        }

        Ok(Self {
            manifest: PluginManifest {
                id: PLUGIN_ID.into(),
                version: env!("CARGO_PKG_VERSION").into(),
                name: "IP Allowlist".into(),
                plugin_class: PluginClass::ToolGate,
                protocol_version: "1.0".into(),
                license: None,
                required_capabilities: Vec::new(),
                tags: Vec::new(),
                provides: Vec::new(),
                provides_schemes: Vec::new(),
                module_path_prefix: ::std::module_path!()
                    .split("::")
                    .next()
                    .unwrap_or("")
                    .to_owned(),
                backend_profile: None,
            },
            networks,
            ip_header: config.ip_header,
            tool_patterns: config.tools,
            host_handle: OnceLock::new(),
        })
    }

    /// Install the unified [`HostHandle`] surface for
    /// per-call observability. Same shape / contract as the
    /// rate-limit plugin's setter — idempotent, returns `false` on
    /// re-install. The SDK factory closure calls this exactly once
    /// at boot, after construction but before traffic.
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    /// Borrow the installed unified host surface.
    /// Returns `None` in test harnesses that constructed the plugin
    /// without calling `set_host_handle`. Callers MUST treat `None`
    /// as "skip the host observability triad".
    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    /// SDK macro factory: parses operator config JSON. A security
    /// control FAILS CLOSED on bad config by REFUSING to instantiate
    /// (panic, caught by the make slot's `catch_panic_to_null_handle`
    /// → null handle → boot Err) — the uniform tool-gate/policy
    /// convention. A silently-degraded deny-all that keeps running is
    /// operationally ambiguous (looks like a different bug); refusing
    /// boot surfaces the config error loudly instead.
    pub fn from_config_json(config_json: &str) -> Self {
        let cfg_value: serde_json::Value = serde_json::from_str(config_json)
            .unwrap_or_else(|err| panic!("ip-allowlist: config JSON failed to parse: {err}"));
        Self::from_config(&cfg_value)
            .unwrap_or_else(|err| panic!("ip-allowlist: config invalid: {err}"))
    }

    fn extract_client_ip(&self, config: &serde_json::Value) -> Option<IpAddr> {
        // Try the configured header from plugin config context
        // The gateway puts request headers in config["_request_headers"]
        if let Some(headers) = config.get("_request_headers").and_then(|h| h.as_object()) {
            // X-Forwarded-For can have comma-separated IPs; take the first (client)
            if let Some(header_val) = headers.get(&self.ip_header).and_then(|v| v.as_str()) {
                let first_ip = header_val.split(',').next().unwrap_or("").trim();
                if let Ok(ip) = first_ip.parse::<IpAddr>() {
                    return Some(normalize_mapped_ipv4(ip));
                }
            }
            // Fallback: try x-real-ip
            if self.ip_header != "x-real-ip"
                && let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.as_str())
                && let Ok(ip) = real_ip.trim().parse::<IpAddr>()
            {
                return Some(normalize_mapped_ipv4(ip));
            }
        }
        None
    }

    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|net| net.contains(ip))
    }

    fn applies_to_tool(&self, tool_name: &str) -> bool {
        if self.tool_patterns.is_empty() {
            return true; // applies to all tools
        }
        self.tool_patterns
            .iter()
            .any(|pattern| glob_match(pattern, tool_name))
    }
}

impl SyncToolGate for IpAllowlistPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn evaluate_pre(
        &self,
        ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _meta: Option<&serde_json::Value>,
        config: &serde_json::Value,
    ) -> GateDecision {
        // Plugin-scoped span so traces from IP allowlist attribute
        // back to dev.mcpg.ip-allowlist. Retained alongside the
        // host-attributed span below.
        let _span = tracing::info_span!(
            "ip_allowlist_evaluate_pre",
            plugin_id = PLUGIN_ID,
            tool = %ctx.tool_name,
        )
        .entered();

        // Open a host-attributed span ALONGSIDE the
        // internal `info_span!` above. The internal span flows
        // through the local `tracing` subscriber; the host span
        // routes to the central observability sink with the plugin
        // alias as a resource attribute.
        //
        // Cardinality note: we put `tool` in span attrs but NOT the
        // resolved client IP — IP addresses are wide-cardinality
        // and would explode span / metric series in real
        // deployments. The IP goes only in audit details (forensic
        // drill-down on a reject).
        let host_span = self.host_handle().map(|h| {
            h.span(
                "ip_allowlist.check",
                serde_json::json!({
                    "tool": ctx.tool_name,
                    "request_id": ctx.request_id,
                    "ip_header": self.ip_header,
                }),
            )
        });

        let started = std::time::Instant::now();
        let (decision, outcome_label, audit_payload) =
            self.evaluate_pre_inner_with_outcome(ctx, config);
        let elapsed = started.elapsed();
        metrics::histogram!("mcpg_ip_allowlist_evaluate_ms").record(elapsed.as_millis() as f64);

        // Unified host-observability triad.
        self.emit_host_observability(ctx, outcome_label, elapsed, audit_payload);

        drop(host_span);

        decision
    }

    fn evaluate_post(
        &self,
        _ctx: &PluginContext,
        _arguments: &serde_json::Value,
        _result: &serde_json::Value,
        _duration_ms: u64,
        _config: &serde_json::Value,
    ) -> GateDecision {
        // IP allowlist is a pre-dispatch gate; post has nothing to
        // say. Always allow.
        GateDecision::allow()
    }
}

impl IpAllowlistPlugin {
    /// Extended return shape: the gate decision plus the host-side
    /// outcome label plus audit details (only consumed on reject
    /// paths).
    fn evaluate_pre_inner_with_outcome(
        &self,
        ctx: &PluginContext,
        config: &serde_json::Value,
    ) -> (GateDecision, &'static str, serde_json::Value) {
        if !self.applies_to_tool(&ctx.tool_name) {
            // Not gated for this tool — treat as allow; no audit.
            return (GateDecision::allow(), "allow", serde_json::Value::Null);
        }

        let Some(client_ip) = self.extract_client_ip(config) else {
            tracing::warn!(
                tool = %ctx.tool_name,
                "IP allowlist: no client IP found in headers, denying"
            );
            metrics::counter!("mcpg_ip_allowlist_decisions_total",
                "decision" => "deny",
                "reason" => "no_ip",
            )
            .increment(1);
            let details = serde_json::json!({
                "tool": ctx.tool_name,
                "reason": "no_client_ip",
                "ip_header": self.ip_header,
                "subject": ctx.identity.subject_id.clone().unwrap_or_default(),
            });
            return (
                GateDecision::Deny {
                    http_status: 403,
                    code: -32030,
                    message: "Access denied: client IP not available".into(),
                    error_data: None,
                },
                "deny_not_allowlisted",
                details,
            );
        };

        if self.is_allowed(&client_ip) {
            metrics::counter!("mcpg_ip_allowlist_decisions_total",
                "decision" => "allow",
                "reason" => "in_allowlist",
            )
            .increment(1);
            (GateDecision::allow(), "allow", serde_json::Value::Null)
        } else {
            tracing::info!(
                tool = %ctx.tool_name,
                client_ip = %client_ip,
                "IP allowlist: client IP not in allowlist"
            );
            metrics::counter!("mcpg_ip_allowlist_decisions_total",
                "decision" => "deny",
                "reason" => "not_in_allowlist",
            )
            .increment(1);
            // IP belongs in audit details for forensic drill-down,
            // NEVER in metric labels (cardinality).
            let details = serde_json::json!({
                "tool": ctx.tool_name,
                "reason": "not_in_allowlist",
                "ip_header": self.ip_header,
                "client_ip": client_ip.to_string(),
                "subject": ctx.identity.subject_id.clone().unwrap_or_default(),
            });
            (
                GateDecision::Deny {
                    http_status: 403,
                    code: -32030,
                    message: format!("Access denied: {client_ip} not in IP allowlist"),
                    error_data: Some(serde_json::json!({
                        "client_ip": client_ip.to_string(),
                    })),
                },
                "deny_not_allowlisted",
                details,
            )
        }
    }

    /// Emit the per-evaluation host-observability triad:
    /// latency histogram + decisions counter + reject audit event,
    /// through the installed [`HostHandle`].
    ///
    /// Cardinality budget: outcome ∈ {allow, deny_not_allowlisted,
    /// error}. The `error` arm is reserved for future engine-
    /// internal failures; today the CIDR check cannot fail (parse
    /// is at construction time, not eval time) and config parse
    /// failures already surface at load time. Declared for symmetry
    /// with the other policy and reliability plugins.
    ///
    /// Audit emission is gated to reject paths:
    ///
    /// - `dev.mcpg.ip_allowlist.rejected` on no-ip-header or
    ///   not-in-allowlist Deny (the audit details carry the
    ///   resolved caller IP when available, or `reason:
    ///   "no_client_ip"` when not).
    /// - `dev.mcpg.ip_allowlist.error` on engine error (reserved).
    ///
    /// Audit emission is moved onto a blocking worker via
    /// `tokio::task::spawn_blocking` and detached — see the
    /// rate-limit plugin's matching helper for the runtime-safety
    /// design notes.
    fn emit_host_observability(
        &self,
        ctx: &PluginContext,
        outcome_label: &'static str,
        duration: std::time::Duration,
        audit_payload: serde_json::Value,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        let elapsed_secs = duration.as_secs_f64();
        host.histogram(
            "mcpg_ip_allowlist_decision_seconds",
            elapsed_secs,
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_ip_allowlist_decisions_total",
            1,
            &[("outcome", outcome_label)],
        );

        let action: Option<&'static str> = match outcome_label {
            "deny_not_allowlisted" => Some("dev.mcpg.ip_allowlist.rejected"),
            "error" => Some("dev.mcpg.ip_allowlist.error"),
            _ => None,
        };
        let Some(action) = action else {
            return;
        };

        let audit_outcome = match outcome_label {
            "error" => AuditOutcome::Failure,
            _ => AuditOutcome::Denied,
        };

        let actor = if ctx.identity.kind.is_empty() {
            synthetic_system_identity()
        } else {
            ctx.identity.clone()
        };
        let resource_uri = format!("tool://{}", ctx.tool_name);
        let mut details = audit_payload;
        if let Some(obj) = details.as_object_mut() {
            obj.insert("alias".into(), serde_json::Value::String(host.alias()));
            obj.insert(
                "duration_ms".into(),
                serde_json::json!(duration.as_millis() as u64),
            );
        }

        let event = AuditEvent {
            event_id: format!("ip-allowlist-{}-{}", ctx.request_id, duration.as_nanos()),
            occurred_at: rfc3339_now(),
            actor,
            action: action.to_owned(),
            resource: Some(resource_uri),
            outcome: audit_outcome,
            request_id: Some(ctx.request_id.clone()),
            upstream_request_id: None,
            node_id: None,
            details,
            prev_event_hash: None,
        };

        let host_for_audit = host.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn_blocking(move || {
                if let Err(err) = host_for_audit.audit_event(event) {
                    tracing::debug!(
                        target: "mcpg::ip_allowlist::host_handle",
                        error = %err,
                        "host_handle.audit_event emission failed"
                    );
                }
            });
        } else {
            if let Err(err) = host_for_audit.audit_event(event) {
                tracing::debug!(
                    target: "mcpg::ip_allowlist::host_handle",
                    error = %err,
                    "host_handle.audit_event emission failed (no runtime)"
                );
            }
        }
    }
}

declare_plugin! {
    plugin_id: PLUGIN_ID,
    plugin_version: env!("CARGO_PKG_VERSION"),
    descriptor_yaml: include_str!("../plugin.yaml"),
    capabilities: &[],
    entities: [
        tool_gate as gate {
            inner_name: "",
            plugin_type: IpAllowlistPlugin,
            // Install the unified `HostHandle` so
            // per-evaluation observability (span + latency
            // histogram + decisions counter + reject audit event)
            // routes through the gateway's central host-services
            // sink. Idempotent — a second install returns false
            // and the slot remains untouched.
            factory: |cfg: &str, host: ::mcpg_plugin_sdk::HostHandle| -> IpAllowlistPlugin {
                let plugin = IpAllowlistPlugin::from_config_json(cfg);
                let _installed = plugin.set_host_handle(host);
                plugin
            },
        }
    ],
}

// ---------------------------------------------------------------------------
// IPv6-mapped IPv4 normalization
// ---------------------------------------------------------------------------

/// Normalize IPv6-mapped IPv4 addresses (::ffff:x.x.x.x) to their inner
/// IPv4 form so that an allowlist entry like `10.0.0.0/8` correctly
/// matches a client connecting from `::ffff:10.0.0.1`. Without this,
/// an attacker behind a dual-stack proxy can bypass IPv4 allowlists.
fn normalize_mapped_ipv4(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

// ---------------------------------------------------------------------------
// Glob matching — delegated to mcpg-glob
// ---------------------------------------------------------------------------

use mcpg_glob::glob_match;

// ---------------------------------------------------------------------------
// Audit event helpers
// ---------------------------------------------------------------------------

/// RFC3339 timestamp for audit events. Mirrors the helper in the
/// policy plugins so cross-plugin audit lines sort identically.
/// Naïve UTC; no leap-second handling.
fn rfc3339_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    let (year, month, day, hour, min, sec) = epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

fn epoch_to_ymdhms(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = secs.div_euclid(86_400);
    let secs_today = secs.rem_euclid(86_400) as u32;
    let hour = secs_today / 3600;
    let min = (secs_today % 3600) / 60;
    let sec = secs_today % 60;
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, min, sec)
}

/// Synthetic identity for audit events on inbound traffic with no
/// caller attribution. Mirrors the policy plugins so cross-plugin
/// audit search treats system traffic uniformly.
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some(PLUGIN_ID.into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_ctx(tool: &str) -> PluginContext {
        PluginContext {
            surface: "tool".to_owned(),
            request_id: "req-1".into(),
            session_id: None,
            tool_name: tool.into(),
            identity: mcpg_plugin_protocol::PluginIdentity {
                kind: "anonymous".into(),
                trust_level: "unauthenticated".into(),
                subject_id: None,
                auth_provider: None,
                issuer: None,
                roles: Vec::new(),
                groups: Vec::new(),
                scopes: Vec::new(),
                attributes: BTreeMap::new(),
            },
            transport: "http".into(),
        }
    }

    fn config_with_headers(headers: &[(&str, &str)]) -> serde_json::Value {
        let header_map: serde_json::Map<String, serde_json::Value> = headers
            .iter()
            .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
            .collect();
        serde_json::json!({ "_request_headers": header_map })
    }

    #[test]
    fn allows_ip_in_cidr() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
        }))
        .unwrap();

        let ctx = test_ctx("tool");
        let config = config_with_headers(&[("x-forwarded-for", "10.1.2.3")]);
        let decision = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        assert!(decision.is_allow());
    }

    #[test]
    fn denies_ip_not_in_cidr() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
        }))
        .unwrap();

        let ctx = test_ctx("tool");
        let config = config_with_headers(&[("x-forwarded-for", "192.168.1.1")]);
        let decision = plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &config);
        match decision {
            GateDecision::Deny {
                http_status, code, ..
            } => {
                assert_eq!(http_status, 403);
                assert_eq!(code, -32030);
            }
            _ => panic!("expected deny"),
        }
    }

    #[test]
    fn denies_when_no_ip_header() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
        }))
        .unwrap();

        let ctx = test_ctx("tool");
        let decision =
            plugin.evaluate_pre(&ctx, &serde_json::json!({}), None, &serde_json::json!({}));
        assert!(
            !decision.is_allow(),
            "should deny when no IP header present"
        );
    }

    #[test]
    fn multiple_cidrs() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8", "172.16.0.0/12", "::1/128"],
        }))
        .unwrap();

        let ctx = test_ctx("tool");

        // 172.16.x.x allowed
        let config = config_with_headers(&[("x-forwarded-for", "172.20.0.1")]);
        assert!(
            plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );

        // IPv6 loopback allowed
        let config = config_with_headers(&[("x-forwarded-for", "::1")]);
        assert!(
            plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );

        // External denied
        let config = config_with_headers(&[("x-forwarded-for", "8.8.8.8")]);
        assert!(
            !plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );
    }

    #[test]
    fn x_forwarded_for_takes_first_ip() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
        }))
        .unwrap();

        let ctx = test_ctx("tool");
        // First IP is the client, rest are proxies
        let config =
            config_with_headers(&[("x-forwarded-for", "10.1.2.3, 192.168.1.1, 172.16.0.1")]);
        assert!(
            plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );
    }

    #[test]
    fn tool_filtering() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
            "tools": ["admin.*"],
        }))
        .unwrap();

        let config = config_with_headers(&[("x-forwarded-for", "192.168.1.1")]);

        // admin.delete — gated, should be denied (not in allowlist)
        let ctx = test_ctx("admin.delete");
        assert!(
            !plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );

        // user.list — not gated, should pass through
        let ctx = test_ctx("user.list");
        assert!(
            plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );
    }

    #[test]
    fn custom_header_name() {
        let plugin = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
            "ip_header": "cf-connecting-ip",
        }))
        .unwrap();

        let ctx = test_ctx("tool");
        let config = config_with_headers(&[("cf-connecting-ip", "10.1.2.3")]);
        assert!(
            plugin
                .evaluate_pre(&ctx, &serde_json::json!({}), None, &config)
                .is_allow()
        );
    }

    #[test]
    fn invalid_cidr_rejected() {
        let result = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["not-a-cidr"],
        }));
        assert!(result.is_err());
    }

    #[test]
    fn config_deserialization() {
        let config: IpAllowlistConfig = serde_json::from_value(serde_json::json!({
            "allow": ["10.0.0.0/8", "::1/128"],
            "ip_header": "x-real-ip",
            "tools": ["admin.*"],
        }))
        .unwrap();
        assert_eq!(config.allow.len(), 2);
        assert_eq!(config.ip_header, "x-real-ip");
        assert_eq!(config.tools, vec!["admin.*"]);
    }

    // -- fail-closed config test ---------------------------------------------

    #[test]
    #[should_panic(expected = "config JSON failed to parse")]
    fn malformed_config_json_panics_fail_closed() {
        // Refuse to instantiate on bad config (panic → null handle → boot
        // Err) rather than silently loading a degraded deny-all.
        let _ = IpAllowlistPlugin::from_config_json("{ not valid json");
    }

    #[test]
    fn unknown_config_key_rejected_fail_closed() {
        // `#[serde(deny_unknown_fields)]` turns a typo'd / renamed /
        // stray operator config key into a parse error. For this
        // security control that means refusing the plugin at boot
        // rather than silently ignoring the bad key.
        let result = IpAllowlistPlugin::from_config(&serde_json::json!({
            "allow": ["10.0.0.0/8"],
            "ip_headre": "x-real-ip", // typo of `ip_header`
        }));
        assert!(
            result.is_err(),
            "unknown config key must be rejected (fail-closed)"
        );
    }
}
