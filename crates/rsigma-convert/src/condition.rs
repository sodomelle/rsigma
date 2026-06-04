use std::collections::HashMap;

use rsigma_parser::*;

use crate::backend::Backend;
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// Recursively walk a `ConditionExpr` tree and convert each node into a query fragment.
pub fn convert_condition_expr(
    backend: &dyn Backend,
    expr: &ConditionExpr,
    detections: &HashMap<String, Detection>,
    state: &mut ConversionState,
) -> Result<String> {
    match expr {
        ConditionExpr::Identifier(name) => {
            let det = detections.get(name).ok_or_else(|| {
                ConvertError::RuleConversion(format!("detection '{name}' not found"))
            })?;
            backend.convert_detection(det, state)
        }

        ConditionExpr::And(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_condition_expr(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_and(&parts)
        }

        ConditionExpr::Or(exprs) => {
            let parts: Vec<String> = exprs
                .iter()
                .map(|e| convert_condition_expr(backend, e, detections, state))
                .collect::<Result<Vec<_>>>()?;
            backend.convert_condition_or(&parts)
        }

        ConditionExpr::Not(inner) => {
            let part = convert_condition_expr(backend, inner, detections, state)?;
            backend.convert_condition_not(&part)
        }

        ConditionExpr::Selector {
            quantifier,
            pattern,
        } => {
            let names: Vec<&String> = detections
                .keys()
                .filter(|n| pattern.matches_detection_name(n))
                .collect();

            if names.is_empty() {
                return Err(ConvertError::RuleConversion(
                    "selector matched no detections".into(),
                ));
            }

            let parts: Vec<String> = names
                .iter()
                .map(|name| {
                    // The name came from `detections.keys()` immediately
                    // above, so this lookup will normally succeed; surface a
                    // clear error rather than panic if the invariant is ever
                    // broken (defensive: no unwrap on shared dispatch paths).
                    let det = detections.get(*name).ok_or_else(|| {
                        ConvertError::RuleConversion(format!(
                            "selector matched detection '{name}' but it disappeared before lookup"
                        ))
                    })?;
                    backend.convert_detection(det, state)
                })
                .collect::<Result<Vec<_>>>()?;

            match quantifier {
                Quantifier::Any | Quantifier::Count(1) => backend.convert_condition_or(&parts),
                Quantifier::All => backend.convert_condition_and(&parts),
                Quantifier::Count(n) => Err(ConvertError::RuleConversion(format!(
                    "'{n} of' quantifier not supported in conversion"
                ))),
            }
        }
    }
}
