//! The `RsigmaMcp` handler, its `ServerHandler` implementation, and the
//! per-tool modules.
//!
//! Each MCP tool lives in its own submodule under `tools/`. A tool is a thin
//! `#[tool]` wrapper over a `run_*` helper that returns `serde_json::Value`;
//! the helpers carry the logic and are unit-tested directly. Errors in the
//! *input* (bad params, unreadable file) surface as MCP errors; errors in the
//! *content* (a rule that fails to parse or convert) come back inside a
//! successful result as `{ "ok": false, ... }` so an agent can read and act on
//! them.
//!
//! Per-tool routers are declared with `#[tool_router(router = ...)]` in each
//! submodule and summed together in [`RsigmaMcp::tool_router`]; rmcp's
//! [`ToolRouter`] implements `Add`, so the combined router exposes every tool
//! exactly as a single `#[tool_router]` block would.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{
        AnnotateAble, Implementation, ListResourcesResult, PaginatedRequestParams, RawResource,
        ReadResourceRequestParams, ReadResourceResult, ResourceContents, ServerCapabilities,
        ServerInfo,
    },
    service::RequestContext,
    tool_handler,
};
use rsigma_parser::reference::{MITRE_TACTICS, MODIFIERS};
use rsigma_parser::{LintConfig, catalogue};
use serde_json::{Value, json};

use shared::to_value;

mod convert_rules;
mod evaluate_events;
mod fix_rules;
mod lint_rules;
mod list_backends;
mod list_builtin_pipelines;
mod list_fields;
mod parse_condition;
mod parse_rule;
mod resolve_pipeline;
mod shared;
mod validate_rules;

/// Shared, immutable server state behind the cloneable handler.
struct State {
    /// Default root for relative path-based tool calls (`--rules-dir`).
    root: Option<PathBuf>,
    /// Lint configuration applied by `lint_rules` and `fix_rules`.
    lint_config: LintConfig,
}

/// The rsigma MCP handler. Cloned per request by rmcp; the real state lives
/// behind an `Arc` so cloning is cheap.
#[derive(Clone)]
pub struct RsigmaMcp {
    tool_router: ToolRouter<Self>,
    state: Arc<State>,
}

impl RsigmaMcp {
    /// Build a handler with an optional default root for path-based calls and a
    /// lint configuration.
    pub fn new(root: Option<PathBuf>, lint_config: LintConfig) -> Self {
        Self {
            tool_router: Self::tool_router(),
            state: Arc::new(State { root, lint_config }),
        }
    }

    fn root(&self) -> Option<&Path> {
        self.state.root.as_deref()
    }

    /// The lint configuration applied by `lint_rules` and `fix_rules`.
    fn lint_config(&self) -> &LintConfig {
        &self.state.lint_config
    }

    /// Combine the per-tool routers into the single router rmcp dispatches over.
    ///
    /// Each submodule contributes a `*_router()` built by `#[tool_router]`;
    /// [`ToolRouter`] implements `Add`, so summing them yields a router holding
    /// all 11 tools.
    fn tool_router() -> ToolRouter<Self> {
        Self::parse_rule_router()
            + Self::parse_condition_router()
            + Self::lint_rules_router()
            + Self::validate_rules_router()
            + Self::evaluate_events_router()
            + Self::convert_rules_router()
            + Self::list_backends_router()
            + Self::list_fields_router()
            + Self::resolve_pipeline_router()
            + Self::list_builtin_pipelines_router()
            + Self::fix_rules_router()
    }
}

impl Default for RsigmaMcp {
    /// A handler with no path root and default lint configuration.
    fn default() -> Self {
        Self::new(None, LintConfig::default())
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for RsigmaMcp {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` and `Implementation` are `#[non_exhaustive]`, so build
        // from `default()` and override the fields we care about.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        info.server_info = Implementation::from_build_env();
        info.server_info.name = "rsigma-mcp".to_string();
        info.server_info.version = env!("CARGO_PKG_VERSION").to_string();
        info.instructions = Some(
            "Sigma detection-rule toolchain: parse, parse_condition, lint, validate, evaluate, \
             convert, fix, list fields, and resolve pipelines. Every tool accepts inline content \
             (e.g. `yaml`) or a file `path`. Resources expose the lint catalogue and modifier / \
             MITRE reference data."
                .to_string(),
        );
        info
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        let resources = vec![
            RawResource::new(RESOURCE_LINT_CATALOGUE, "Lint rule catalogue").no_annotation(),
            RawResource::new(RESOURCE_MODIFIERS, "Sigma field modifiers").no_annotation(),
            RawResource::new(RESOURCE_MITRE_TACTICS, "MITRE ATT&CK tactics").no_annotation(),
        ];
        Ok(ListResourcesResult {
            resources,
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let value = match request.uri.as_str() {
            RESOURCE_LINT_CATALOGUE => to_value(&catalogue()),
            RESOURCE_MODIFIERS => reference_pairs_json(MODIFIERS),
            RESOURCE_MITRE_TACTICS => reference_pairs_json(MITRE_TACTICS),
            other => {
                return Err(McpError::resource_not_found(
                    format!("unknown resource '{other}'"),
                    None,
                ));
            }
        };
        let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            text,
            &request.uri,
        )]))
    }
}

const RESOURCE_LINT_CATALOGUE: &str = "rsigma://lint/catalogue";
const RESOURCE_MODIFIERS: &str = "rsigma://reference/modifiers";
const RESOURCE_MITRE_TACTICS: &str = "rsigma://reference/mitre-tactics";

/// Render a `(name, description)` reference table as a JSON array of objects.
fn reference_pairs_json(pairs: &[(&str, &str)]) -> Value {
    Value::Array(
        pairs
            .iter()
            .map(|(name, description)| json!({ "name": name, "description": description }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::convert_rules::ConvertInput;
    use super::evaluate_events::EvaluateInput;
    use super::fix_rules::FixInput;
    use super::list_backends::run_list_backends;
    use super::list_builtin_pipelines::run_list_builtin_pipelines;
    use super::list_fields::FieldsInput;
    use super::parse_condition::{ConditionInput, run_parse_condition};
    use super::resolve_pipeline::ResolvePipelineInput;
    use super::shared::SourceInput;
    use super::validate_rules::ValidateInput;
    use super::*;

    fn handler() -> RsigmaMcp {
        RsigmaMcp::new(None, LintConfig::default())
    }

    const VALID_RULE: &str = r#"
title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami
author: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#;

    fn src(yaml: &str) -> SourceInput {
        SourceInput {
            yaml: Some(yaml.to_string()),
            path: None,
        }
    }

    #[test]
    fn parse_rule_happy_path() {
        let v = handler().run_parse_rule(src(VALID_RULE)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["rule_count"], 1);
    }

    #[test]
    fn parse_rule_invalid_yaml_reports_error() {
        let v = handler()
            .run_parse_rule(src("title: [unterminated"))
            .unwrap();
        assert_eq!(v["ok"], false);
        assert!(!v["parse_errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn parse_rule_requires_input() {
        let err = handler()
            .run_parse_rule(SourceInput {
                yaml: None,
                path: None,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("required"));
    }

    #[test]
    fn parse_condition_happy_and_error() {
        let ok = run_parse_condition(ConditionInput {
            condition: "sel and not 1 of filter_*".to_string(),
        });
        assert_eq!(ok["ok"], true);
        let bad = run_parse_condition(ConditionInput {
            condition: "sel and and".to_string(),
        });
        assert_eq!(bad["ok"], false);
    }

    #[test]
    fn lint_rules_flags_invalid_status() {
        // `expreimental` is within edit distance of `experimental`, so the
        // finding carries a safe fix (fixable == true).
        let yaml = "title: T\nstatus: expreimental\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\nlevel: medium\n";
        let v = handler().run_lint_rules(src(yaml)).unwrap();
        assert_eq!(v["ok"], false);
        let findings = v["files"][0]["findings"].as_array().unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f["rule"] == "invalid_status" && f["fixable"] == true)
        );
    }

    #[test]
    fn lint_rules_clean_rule_ok() {
        let v = handler().run_lint_rules(src(VALID_RULE)).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["summary"]["errors"], 0);
    }

    #[tokio::test]
    async fn validate_rules_ok_and_compile_error() {
        let ok = handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                pipelines: vec![],
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(ok["ok"], true);

        let bad_yaml = "title: T\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: missing_ref\n";
        let bad = handler()
            .run_validate_rules(ValidateInput {
                yaml: Some(bad_yaml.to_string()),
                path: None,
                pipelines: vec![],
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(bad["ok"], false);
        assert!(!bad["compile_errors"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_events_detects_match() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: Some("summary".to_string()),
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["summary"]["detection_matches"], 1);
        assert_eq!(v["results"][0]["event_index"], 0);
    }

    #[tokio::test]
    async fn evaluate_events_requires_events() {
        let err = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: None,
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("events"));
    }

    #[tokio::test]
    async fn evaluate_events_with_template_enricher() {
        let enrichers = r#"
enrichers:
  - id: runbook
    kind: detection
    type: template
    inject_field: runbook_url
    template: "https://wiki/${detection.rule.id}"
"#;
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: Some(enrichers.to_string()),
                enrichers_path: None,
            })
            .await
            .unwrap();
        assert_eq!(v["summary"]["enriched"], true);
        let enrichments = &v["results"][0]["result"]["enrichments"];
        assert_eq!(
            enrichments["runbook_url"],
            "https://wiki/8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a"
        );
    }

    #[tokio::test]
    async fn evaluate_events_invalid_enricher_config_errors() {
        let enrichers = r#"
enrichers:
  - id: bad
    kind: detection
    type: template
    inject_field: out
    template: "https://wiki/${correlation.rule.id}"
"#;
        let err = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                events: Some(vec![json!({ "CommandLine": "cmd /c whoami" })]),
                events_path: None,
                pipelines: vec![],
                match_detail: None,
                timestamp_fields: vec![],
                enrichers: Some(enrichers.to_string()),
                enrichers_path: None,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("namespace"));
    }

    #[test]
    fn convert_rules_postgres_and_unknown_target() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert!(!v["queries"].as_array().unwrap().is_empty());

        let err = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                target: "nope".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("unknown target"));
    }

    #[test]
    fn list_backends_includes_postgres() {
        let v = run_list_backends().unwrap();
        let targets: Vec<&str> = v["backends"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["target"].as_str().unwrap())
            .collect();
        assert!(targets.contains(&"postgres"));
        assert!(targets.contains(&"fibratus"));
    }

    #[test]
    fn list_fields_reports_command_line() {
        let v = handler()
            .run_list_fields(FieldsInput {
                yaml: Some(VALID_RULE.to_string()),
                path: None,
                pipelines: vec![],
                include_filters: true,
            })
            .unwrap();
        let names: Vec<&str> = v["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["field"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"CommandLine"));
    }

    #[tokio::test]
    async fn resolve_pipeline_builtin() {
        let v = handler()
            .run_resolve_pipeline(ResolvePipelineInput {
                pipeline: "sysmon".to_string(),
                resolve_sources: false,
            })
            .await
            .unwrap();
        assert_eq!(v["name"], "sysmon");
        assert_eq!(v["is_dynamic"], false);
    }

    #[tokio::test]
    async fn resolve_pipeline_unknown_is_error() {
        let err = handler()
            .run_resolve_pipeline(ResolvePipelineInput {
                pipeline: "definitely_not_a_pipeline.yml".to_string(),
                resolve_sources: false,
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("pipeline"));
    }

    #[test]
    fn list_builtin_pipelines_lists_three() {
        let v = run_list_builtin_pipelines();
        let names: Vec<&str> = v["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"ecs_windows"));
        assert!(names.contains(&"fibratus_windows"));
        assert!(names.contains(&"sysmon"));
    }

    // ---- Golden tests (committed insta snapshots) -----------------------

    const GOLDEN_RULE: &str = r#"
title: Whoami Execution
id: 8b1d8c97-5b3a-4d77-9b48-7c5f7c8b1a2a
status: test
description: Detects whoami execution
author: rsigma
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
level: medium
tags:
    - attack.execution
"#;

    #[test]
    fn golden_lint_rules() {
        // A rule with a fixable typo and a missing field, for a stable finding set.
        let yaml = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler().run_lint_rules(src(yaml)).unwrap();
        // `sort_maps` keeps the snapshot stable regardless of whether
        // serde_json's `preserve_order` feature is unified in by the build.
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("lint_rules", v);
        });
    }

    #[test]
    fn golden_convert_rules_postgres() {
        let v = handler()
            .run_convert_rules(ConvertInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                target: "postgres".to_string(),
                format: None,
                pipelines: vec![],
                options: HashMap::new(),
                skip_unsupported: false,
            })
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("convert_rules_postgres", v);
        });
    }

    #[test]
    fn fix_rules_applies_safe_fix() {
        let yaml = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec![],
                write: false,
            })
            .unwrap();
        assert_eq!(v["ok"], true);
        assert!(v["applied"].as_u64().unwrap() >= 1);
        assert_eq!(v["skipped_unsafe"], 0);
        assert_eq!(v["written"], false);
        let fixed = v["fixed_yaml"].as_str().unwrap();
        assert!(fixed.contains("status: test"));
        assert!(!fixed.contains("Status: test"));
    }

    #[test]
    fn fix_rules_lint_rule_filter() {
        // Restrict to a lint rule that does not fire here, so nothing applies.
        let yaml = "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec!["duplicate_tags".to_string()],
                write: false,
            })
            .unwrap();
        assert_eq!(v["applied"], 0);
        assert_eq!(v["changed"], false);
    }

    #[test]
    fn fix_rules_write_without_path_is_error() {
        let err = handler()
            .run_fix_rules(FixInput {
                yaml: Some("title: T\nStatus: test\n".to_string()),
                path: None,
                lint_rules: vec![],
                write: true,
            })
            .unwrap_err();
        assert!(format!("{err:?}").contains("write"));
    }

    #[test]
    fn fix_rules_write_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yml");
        std::fs::write(
            &path,
            "title: T\nStatus: test\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
        )
        .unwrap();

        let v = handler()
            .run_fix_rules(FixInput {
                yaml: None,
                path: Some(path.display().to_string()),
                lint_rules: vec![],
                write: true,
            })
            .unwrap();
        assert_eq!(v["written"], true);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("status: test"));
    }

    #[test]
    fn golden_fix_rules() {
        let yaml = "title: T\nStatus: test\ntags:\n  - attack.execution\n  - attack.execution\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: b\n  condition: sel\n";
        let v = handler()
            .run_fix_rules(FixInput {
                yaml: Some(yaml.to_string()),
                path: None,
                lint_rules: vec![],
                write: false,
            })
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("fix_rules", v);
        });
    }

    #[test]
    fn reference_resources_round_trip() {
        // The data behind the MCP reference resources.
        let modifiers = reference_pairs_json(MODIFIERS);
        assert!(
            modifiers
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["name"] == "contains")
        );
        let cat = to_value(&catalogue());
        assert_eq!(cat.as_array().unwrap().len(), 75);
    }

    #[tokio::test]
    async fn golden_evaluate_events() {
        let v = handler()
            .run_evaluate_events(EvaluateInput {
                yaml: Some(GOLDEN_RULE.to_string()),
                path: None,
                events: Some(vec![
                    json!({ "CommandLine": "cmd /c whoami /priv" }),
                    json!({ "CommandLine": "ipconfig /all" }),
                ]),
                events_path: None,
                pipelines: vec![],
                match_detail: Some("summary".to_string()),
                timestamp_fields: vec![],
                enrichers: None,
                enrichers_path: None,
            })
            .await
            .unwrap();
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!("evaluate_events", v);
        });
    }
}
