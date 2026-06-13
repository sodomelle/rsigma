//! The `lint_rules` tool: lint Sigma rules against the specification.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::{
    LintWarning, Severity, lint_yaml_directory_with_config, lint_yaml_file_with_config,
    lint_yaml_str_with_config,
};
use serde_json::{Value, json};

use crate::input::resolve_path;

use super::RsigmaMcp;
use super::shared::{SourceInput, invalid, json_result, warning_json};

#[tool_router(router = lint_rules_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Lint Sigma rules against the specification.
    #[tool(
        description = "Lint Sigma rules against the specification, returning findings with lint rule id, severity, message, line, and whether an auto-fix is available. Accepts inline `yaml`, a file `path`, or a directory `path`."
    )]
    async fn lint_rules(
        &self,
        Parameters(input): Parameters<SourceInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_lint_rules(input)?))
    }

    pub(crate) fn run_lint_rules(&self, input: SourceInput) -> Result<Value, McpError> {
        let cfg = self.lint_config();
        let findings: Vec<(String, Vec<LintWarning>)> =
            match (input.yaml.as_deref(), input.path.as_deref()) {
                (Some(_), Some(_)) => {
                    return Err(invalid("provide either `yaml` or `path`, not both"));
                }
                (None, None) => return Err(invalid("one of `yaml` or `path` is required")),
                (Some(text), None) => {
                    vec![("<inline>".to_string(), lint_yaml_str_with_config(text, cfg))]
                }
                (None, Some(p)) => {
                    let path = resolve_path(p, self.root());
                    if path.is_dir() {
                        lint_yaml_directory_with_config(&path, cfg)
                            .map_err(|e| invalid(format!("cannot lint '{}': {e}", path.display())))?
                            .into_iter()
                            .map(|r| (r.path.display().to_string(), r.warnings))
                            .collect()
                    } else {
                        let r = lint_yaml_file_with_config(&path, cfg).map_err(|e| {
                            invalid(format!("cannot lint '{}': {e}", path.display()))
                        })?;
                        vec![(r.path.display().to_string(), r.warnings)]
                    }
                }
            };

        let (mut errors, mut warnings, mut infos, mut hints) = (0usize, 0usize, 0usize, 0usize);
        let mut files = Vec::new();
        for (path, ws) in &findings {
            for w in ws {
                match w.severity {
                    Severity::Error => errors += 1,
                    Severity::Warning => warnings += 1,
                    Severity::Info => infos += 1,
                    Severity::Hint => hints += 1,
                }
            }
            files.push(json!({
                "path": path,
                "findings": ws.iter().map(warning_json).collect::<Vec<_>>(),
            }));
        }

        Ok(json!({
            "ok": errors == 0,
            "summary": {
                "files": findings.len(),
                "errors": errors,
                "warnings": warnings,
                "infos": infos,
                "hints": hints,
            },
            "files": files,
        }))
    }
}
