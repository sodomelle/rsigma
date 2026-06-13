//! The `parse_rule` tool: parse Sigma YAML into a structured AST as JSON.

use rmcp::{
    ErrorData as McpError, handler::server::wrapper::Parameters, model::CallToolResult, tool,
    tool_router,
};
use rsigma_parser::parse_sigma_yaml;
use serde_json::{Value, json};

use super::RsigmaMcp;
use super::shared::{SourceInput, json_result};

#[tool_router(router = parse_rule_router, vis = "pub(crate)")]
impl RsigmaMcp {
    /// Parse Sigma YAML (rules, correlations, filters; multi-document) to AST JSON.
    #[tool(
        description = "Parse Sigma YAML (rules, correlations, filters; multi-document supported) into a structured AST as JSON, or return structured parse errors. Accepts inline `yaml` or a file `path`."
    )]
    async fn parse_rule(
        &self,
        Parameters(input): Parameters<SourceInput>,
    ) -> Result<CallToolResult, McpError> {
        Ok(json_result(&self.run_parse_rule(input)?))
    }

    pub(crate) fn run_parse_rule(&self, input: SourceInput) -> Result<Value, McpError> {
        let (source, _) = self.load_source(input.yaml.as_deref(), input.path.as_deref())?;
        Ok(match parse_sigma_yaml(&source) {
            Ok(collection) => json!({
                // `parse_sigma_yaml` records syntax errors in `errors` rather
                // than returning `Err`, so `ok` reflects whether parsing was clean.
                "ok": collection.errors.is_empty(),
                "rule_count": collection.rules.len(),
                "correlation_count": collection.correlations.len(),
                "filter_count": collection.filters.len(),
                "parse_errors": collection.errors,
                "collection": collection,
            }),
            Err(e) => json!({ "ok": false, "error": e.to_string() }),
        })
    }
}
