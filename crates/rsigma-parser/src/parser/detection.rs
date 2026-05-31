use std::collections::HashMap;

use yaml_serde::Value;

use crate::ast::*;
use crate::condition::parse_condition;
use crate::error::{Result, SigmaParserError};
use crate::value::SigmaValue;

use super::{
    collect_custom_attributes, get_str, get_str_list, parse_logsource, parse_related, val_key,
};

// =============================================================================
// Detection Rule Parsing
// =============================================================================

/// Parse a detection rule from a YAML value.
///
/// Reference: pySigma rule.py SigmaRule.from_yaml / from_dict
pub(super) fn parse_detection_rule(value: &Value) -> Result<SigmaRule> {
    let m = value
        .as_mapping()
        .ok_or_else(|| SigmaParserError::InvalidRule("Expected a YAML mapping".into()))?;

    let title = get_str(m, "title")
        .ok_or_else(|| SigmaParserError::MissingField("title".into()))?
        .to_string();

    let detection_val = m
        .get(val_key("detection"))
        .ok_or_else(|| SigmaParserError::MissingField("detection".into()))?;
    let detection = parse_detections(detection_val)?;

    let logsource = m
        .get(val_key("logsource"))
        .map(parse_logsource)
        .transpose()?
        .unwrap_or_default();

    // Custom attributes: merge arbitrary top-level keys and the entries of the
    // dedicated `custom_attributes:` mapping. Entries in `custom_attributes:`
    // win over a top-level key of the same name (last-write-wins).
    // Mirrors pySigma's `SigmaRule.custom_attributes` dict.
    let standard_rule_keys: &[&str] = &[
        "title",
        "id",
        "related",
        "name",
        "taxonomy",
        "status",
        "description",
        "license",
        "author",
        "references",
        "date",
        "modified",
        "logsource",
        "detection",
        "fields",
        "falsepositives",
        "level",
        "tags",
        "scope",
        "custom_attributes",
    ];
    let custom_attributes = collect_custom_attributes(m, standard_rule_keys);

    Ok(SigmaRule {
        title,
        logsource,
        detection,
        id: get_str(m, "id").map(|s| s.to_string()),
        name: get_str(m, "name").map(|s| s.to_string()),
        related: parse_related(m.get(val_key("related"))),
        taxonomy: get_str(m, "taxonomy").map(|s| s.to_string()),
        status: get_str(m, "status").and_then(|s| s.parse().ok()),
        description: get_str(m, "description").map(|s| s.to_string()),
        license: get_str(m, "license").map(|s| s.to_string()),
        author: get_str(m, "author").map(|s| s.to_string()),
        references: get_str_list(m, "references"),
        date: get_str(m, "date").map(|s| s.to_string()),
        modified: get_str(m, "modified").map(|s| s.to_string()),
        fields: get_str_list(m, "fields"),
        falsepositives: get_str_list(m, "falsepositives"),
        level: get_str(m, "level").and_then(|s| s.parse().ok()),
        tags: get_str_list(m, "tags"),
        scope: get_str_list(m, "scope"),
        custom_attributes,
    })
}

// =============================================================================
// Detection Section Parsing
// =============================================================================

/// Parse the `detection:` section of a rule.
///
/// The detection section contains:
/// - `condition`: string or list of strings
/// - `timeframe`: optional duration string
/// - Everything else: named detection identifiers
///
/// Reference: pySigma rule/detection.py SigmaDetections.from_dict
pub(super) fn parse_detections(value: &Value) -> Result<Detections> {
    let m = value.as_mapping().ok_or_else(|| {
        SigmaParserError::InvalidDetection("Detection section must be a mapping".into())
    })?;

    // Extract condition (required)
    let condition_val = m
        .get(val_key("condition"))
        .ok_or_else(|| SigmaParserError::MissingField("condition".into()))?;

    let condition_strings = match condition_val {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => {
            let mut strings = Vec::with_capacity(seq.len());
            for v in seq {
                match v.as_str() {
                    Some(s) => strings.push(s.to_string()),
                    None => {
                        return Err(SigmaParserError::InvalidDetection(format!(
                            "condition list items must be strings, got: {v:?}"
                        )));
                    }
                }
            }
            strings
        }
        _ => {
            return Err(SigmaParserError::InvalidDetection(
                "condition must be a string or list of strings".into(),
            ));
        }
    };

    // Parse each condition string
    let conditions: Vec<ConditionExpr> = condition_strings
        .iter()
        .map(|s| parse_condition(s))
        .collect::<Result<Vec<_>>>()?;

    // Extract optional timeframe
    let timeframe = get_str(m, "timeframe").map(|s| s.to_string());

    // Parse all named detections (everything except condition and timeframe)
    let mut named = HashMap::new();
    for (key, val) in m {
        let key_str = key.as_str().unwrap_or("");
        if key_str == "condition" || key_str == "timeframe" {
            continue;
        }
        named.insert(key_str.to_string(), parse_detection(val)?);
    }

    Ok(Detections {
        named,
        conditions,
        condition_strings,
        timeframe,
    })
}

/// Parse a single named detection definition.
///
/// A detection can be:
/// 1. A mapping (key-value pairs, AND-linked)
/// 2. A list of plain values (keyword detection)
/// 3. A list of mappings (OR-linked sub-detections)
///
/// Reference: pySigma rule/detection.py SigmaDetection.from_definition
fn parse_detection(value: &Value) -> Result<Detection> {
    match value {
        Value::Mapping(m) => {
            // Case 1: key-value mapping → AND-linked detection items.
            //
            // Keys without an array quantifier (`[any]`/`[all]`) become plain
            // detection items exactly as before. Keys carrying a quantifier
            // desugar into `Detection::ArrayMatch` object-scope blocks. A map
            // with no blocks stays an `AllOf`; a single block becomes that
            // block; a mix becomes an `And`.
            let mut items: Vec<DetectionItem> = Vec::new();
            let mut blocks: Vec<Detection> = Vec::new();
            for (k, v) in m.iter() {
                match parse_map_entry(k.as_str().unwrap_or(""), v)? {
                    ParsedEntry::Item(item) => items.push(item),
                    ParsedEntry::Block(block) => blocks.push(block),
                }
            }

            if blocks.is_empty() {
                Ok(Detection::AllOf(items))
            } else if items.is_empty() && blocks.len() == 1 {
                Ok(blocks.into_iter().next().expect("len checked"))
            } else {
                let mut parts: Vec<Detection> = Vec::new();
                if !items.is_empty() {
                    parts.push(Detection::AllOf(items));
                }
                parts.extend(blocks);
                Ok(Detection::And(parts))
            }
        }
        Value::Sequence(seq) => {
            // Check if all items are plain values (strings/numbers/etc.)
            let all_plain = seq.iter().all(|v| !v.is_mapping() && !v.is_sequence());
            if all_plain {
                // Case 2: list of plain values → keyword detection
                let values = seq.iter().map(SigmaValue::from_yaml).collect();
                Ok(Detection::Keywords(values))
            } else {
                // Case 3: list of mappings → OR-linked sub-detections
                let subs: Vec<Detection> = seq
                    .iter()
                    .map(parse_detection)
                    .collect::<Result<Vec<_>>>()?;
                Ok(Detection::AnyOf(subs))
            }
        }
        // Plain value → single keyword
        _ => Ok(Detection::Keywords(vec![SigmaValue::from_yaml(value)])),
    }
}

/// Parse a single detection item from a key-value pair.
///
/// The key contains the field name and optional modifiers separated by `|`:
/// - `EventType` → field="EventType", no modifiers
/// - `TargetObject|endswith` → field="TargetObject", modifiers=[EndsWith]
/// - `Destination|contains|all` → field="Destination", modifiers=[Contains, All]
///
/// Reference: pySigma rule/detection.py SigmaDetectionItem.from_mapping
fn parse_detection_item(key: &str, value: &Value) -> Result<DetectionItem> {
    let field = parse_field_spec(key)?;

    let values = match value {
        Value::Sequence(seq) => seq.iter().map(|v| to_sigma_value(v, &field)).collect(),
        _ => vec![to_sigma_value(value, &field)],
    };

    Ok(DetectionItem { field, values })
}

// =============================================================================
// Array matching: object-scope quantifier blocks
// =============================================================================
//
// Proposed Sigma array-matching extension (sigma-specification Discussion #106).
// A detection key whose field path carries an array quantifier (`[any]`/`[all]`)
// desugars into a `Detection::ArrayMatch`:
//
//   connections[any]:            ArrayMatch { field: "connections", quantifier: Any,
//     protocol: "TCP"      ==>       body: AllOf([protocol == "TCP", ip cidr ...]) }
//     ip|cidr: "10.0.0.0/8"
//
//   connections[any].ip: "x" ==> ArrayMatch { field: "connections", quantifier: Any,
//                                              body: AllOf([ip == "x"]) }
//
// Keys with no quantifier are untouched and parse exactly as before.

/// A parsed field-path segment: a name plus an optional array quantifier.
struct PathSegment {
    name: String,
    quantifier: Option<ArrayQuantifier>,
}

/// The result of parsing one mapping entry: either a plain detection item or an
/// array object-scope block.
enum ParsedEntry {
    Item(DetectionItem),
    Block(Detection),
}

/// Parse one `key: value` mapping entry, desugaring array quantifiers.
fn parse_map_entry(key: &str, value: &Value) -> Result<ParsedEntry> {
    // Split the field path from the trailing modifier chain (`field|mod1|mod2`).
    let (field_part, modifier_part) = match key.split_once('|') {
        Some((f, m)) => (f, Some(m)),
        None => (key, None),
    };

    // Empty field part (keyword-style key or bare modifiers): defer to the
    // existing field-spec parser, which already handles these cases.
    if field_part.is_empty() {
        return Ok(ParsedEntry::Item(parse_detection_item(key, value)?));
    }

    let segments = parse_field_path(field_part)?;
    match segments.iter().position(|s| s.quantifier.is_some()) {
        // No array quantifier anywhere: a plain detection item, unchanged.
        None => Ok(ParsedEntry::Item(parse_detection_item(key, value)?)),
        Some(idx) => {
            let quantifier = segments[idx]
                .quantifier
                .expect("position found a quantifier");
            // The array lives at the path up to and including the quantified
            // segment.
            let array_field = segments[..=idx]
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(".");
            let body = build_block_body(&segments[idx + 1..], modifier_part, value)?;
            Ok(ParsedEntry::Block(Detection::ArrayMatch {
                field: array_field,
                quantifier,
                body: Box::new(body),
            }))
        }
    }
}

/// Build the nested detection that an array block evaluates per member.
fn build_block_body(
    remaining: &[PathSegment],
    modifier_part: Option<&str>,
    value: &Value,
) -> Result<Detection> {
    if remaining.is_empty() {
        // The quantifier was on the final path segment.
        match value {
            // `field[any]: { sub-map }` → object-scope block over member fields.
            Value::Mapping(_) => {
                if modifier_part.is_some() {
                    return Err(SigmaParserError::InvalidFieldSpec(
                        "value modifiers cannot be applied to an array object-scope block; \
                         move the modifier onto a field inside the block"
                            .into(),
                    ));
                }
                parse_detection(value)
            }
            // `field[all]: value` (or a list) → match the array member itself.
            // Represented as a body item with no field name.
            _ => {
                let modifiers = parse_modifiers(modifier_part)?;
                let field = FieldSpec::new(None, modifiers);
                let values = match value {
                    Value::Sequence(seq) => seq.iter().map(|v| to_sigma_value(v, &field)).collect(),
                    _ => vec![to_sigma_value(value, &field)],
                };
                Ok(Detection::AllOf(vec![DetectionItem { field, values }]))
            }
        }
    } else {
        // A quantifier in the middle of the path: recurse on the remainder so
        // further quantifiers and the leaf predicate desugar correctly.
        let remaining_key = reconstruct_key(remaining, modifier_part);
        match parse_map_entry(&remaining_key, value)? {
            ParsedEntry::Item(item) => Ok(Detection::AllOf(vec![item])),
            ParsedEntry::Block(block) => Ok(block),
        }
    }
}

/// Split a field path into dot-separated segments, recognizing the array
/// quantifiers `[any]` and `[all]` on the tail of a segment.
///
/// Only a well-formed `name[any]` / `name[all]` is treated as a quantifier.
/// An unknown bracket token (e.g. `[0]`, positional indexing, which is out of
/// scope for this extension) is a parse error so typos surface instead of
/// silently matching a literal field name with brackets.
fn parse_field_path(field_part: &str) -> Result<Vec<PathSegment>> {
    let mut segments = Vec::new();
    for raw in field_part.split('.') {
        if raw.ends_with(']')
            && let Some(open) = raw.find('[')
        {
            let name = &raw[..open];
            let token = &raw[open + 1..raw.len() - 1];
            let quantifier = match token {
                "any" => ArrayQuantifier::Any,
                "all" => ArrayQuantifier::All,
                other => {
                    return Err(SigmaParserError::InvalidFieldSpec(format!(
                        "unknown array quantifier '[{other}]' in field '{field_part}'; \
                         only [any] and [all] are supported (positional indexing is not)"
                    )));
                }
            };
            if name.is_empty() {
                return Err(SigmaParserError::InvalidFieldSpec(format!(
                    "array quantifier without a field name in '{field_part}'"
                )));
            }
            segments.push(PathSegment {
                name: name.to_string(),
                quantifier: Some(quantifier),
            });
        } else {
            segments.push(PathSegment {
                name: raw.to_string(),
                quantifier: None,
            });
        }
    }
    Ok(segments)
}

/// Parse the pipe-separated modifier chain that follows the first `|` in a key.
fn parse_modifiers(modifier_part: Option<&str>) -> Result<Vec<Modifier>> {
    let mut modifiers = Vec::new();
    if let Some(part) = modifier_part {
        for mod_str in part.split('|') {
            if mod_str == "not" {
                return Err(SigmaParserError::NotIsNotAModifier);
            }
            let m = mod_str
                .parse::<Modifier>()
                .map_err(|_| SigmaParserError::UnknownModifier(mod_str.to_string()))?;
            modifiers.push(m);
        }
    }
    Ok(modifiers)
}

/// Rebuild a detection key string from path segments plus an optional modifier
/// chain, re-appending `[any]`/`[all]` markers.
fn reconstruct_key(segments: &[PathSegment], modifier_part: Option<&str>) -> String {
    let path = segments
        .iter()
        .map(|s| match s.quantifier {
            Some(q) => format!("{}[{q}]", s.name),
            None => s.name.clone(),
        })
        .collect::<Vec<_>>()
        .join(".");
    match modifier_part {
        Some(m) => format!("{path}|{m}"),
        None => path,
    }
}

/// Convert a YAML value to a SigmaValue, respecting field modifiers.
///
/// When the `re` modifier is present, strings are treated as raw (no wildcard parsing).
fn to_sigma_value(v: &Value, field: &FieldSpec) -> SigmaValue {
    if field.has_modifier(Modifier::Re)
        && let Value::String(s) = v
    {
        return SigmaValue::from_raw_string(s);
    }
    SigmaValue::from_yaml(v)
}

/// Parse a field specification string like `"TargetObject|endswith"`.
///
/// Reference: pySigma rule/detection.py — `field, *modifier_ids = key.split("|")`
pub fn parse_field_spec(key: &str) -> Result<FieldSpec> {
    if key.is_empty() {
        return Ok(FieldSpec::new(None, Vec::new()));
    }

    let parts: Vec<&str> = key.split('|').collect();
    let field_name = parts[0];
    let field = if field_name.is_empty() {
        None
    } else {
        Some(field_name.to_string())
    };

    let mut modifiers = Vec::new();
    for &mod_str in &parts[1..] {
        // Sigma reserves `not` for condition expressions; it is not a value
        // modifier. Catch this idiom up front so the diagnostic explains
        // the workaround instead of just saying "unknown modifier".
        if mod_str == "not" {
            return Err(SigmaParserError::NotIsNotAModifier);
        }
        let m = mod_str
            .parse::<Modifier>()
            .map_err(|_| SigmaParserError::UnknownModifier(mod_str.to_string()))?;
        modifiers.push(m);
    }

    Ok(FieldSpec::new(field, modifiers))
}
