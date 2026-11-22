//! Pure, fail-closed fixture redaction. No provider-owned key or free text is
//! copied unless it is a reviewed protocol literal. Null/absence, empty values,
//! arrays, wrappers and primitive types remain as observed.
use super::{Failure, Provider};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const CARTA_KEYS: &[&str] = &[
    "access_token",
    "expires_in",
    "token_type",
    "scope",
    "stakeholders",
    "optionGrants",
    "nextPageToken",
    "id",
    "issuerId",
    "stakeholderId",
    "fullName",
    "email",
    "employeeId",
    "relationship",
    "group",
    "entityType",
    "address",
    "country",
    "equityIncentivePlanName",
    "issueDate",
    "vestingStartDate",
    "boardApprovalDate",
    "stakeholderAcceptanceDate",
    "grantExpirationDate",
    "isoNsoSplit",
    "stockOptionType",
    "quantity",
    "outstandingQuantity",
    "vestedQuantity",
    "exercisedQuantity",
    "exercisePrice",
    "currencyCode",
    "amount",
    "value",
    "securityLabel",
    "earlyExercisable",
    "vestingEvents",
    "exercises",
    "vestingSchedule",
    "lastModifiedDatetime",
    "vestDate",
    "isoQuantity",
    "nsoQuantity",
    "performanceCondition",
    "vested",
    "maxQuantity",
    "targetQuantity",
    "exerciseId",
    "fairMarketValueAsOfDate",
    "exerciseDate",
    "status",
    "certificateId",
    "exerciseType",
    "qualified",
    "name",
    "lastModifiedDate",
    "startDate",
    "endDate",
];
const OPENAI_KEYS: &[&str] = &[
    "id",
    "object",
    "created_at",
    "completed_at",
    "status",
    "error",
    "incomplete_details",
    "instructions",
    "max_output_tokens",
    "model",
    "output",
    "type",
    "role",
    "content",
    "text",
    "annotations",
    "logprobs",
    "summary",
    "reasoning",
    "effort",
    "encrypted_content",
    "parallel_tool_calls",
    "previous_response_id",
    "store",
    "background",
    "tools",
    "tool_choice",
    "service_tier",
    "temperature",
    "top_p",
    "truncation",
    "usage",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "input_tokens_details",
    "output_tokens_details",
    "cached_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "user",
    "metadata",
    "format",
    "verbosity",
    "refusal",
    "safety_identifier",
    "prompt_cache_key",
    "prompt_cache_retention",
    "top_logprobs",
    "max_tool_calls",
    "reason",
    "code",
    "message",
    "param",
    "billing",
    "payer",
];
const SCOPES: &[&str] = &[
    "read_issuer_stakeholders",
    "read_issuer_securities",
    "read_issuer_capitalizationtablesummary",
    "read_issuer_securitiestemplates",
    "read_issuer_info",
    "read_issuer_valuations",
    "read_issuer_stakeholdercapitalizationtable",
    "read_issuer_shareclasses",
    "read_issuer_interests",
    "read_issuer_draftsecurities",
];

#[derive(Default)]
pub(super) struct Redactor {
    identifiers: BTreeMap<(String, String), u64>,
    selected_issuer: Option<u64>,
}

impl Redactor {
    pub(super) fn validate_identities(&self, provider: Provider) -> Result<(), Failure> {
        let replacements = self
            .identifiers
            .values()
            .map(|id| match provider {
                Provider::Carta => format!("{}", 1000 + id),
                Provider::OpenAi => format!("redacted_{id}"),
            })
            .collect::<std::collections::BTreeSet<_>>();
        if self.identifiers.keys().any(|(class, value)| {
            let value = if class == "issuer" {
                value.as_str()
            } else {
                value
                    .strip_prefix("string:")
                    .or_else(|| value.strip_prefix("number:"))
                    .unwrap_or(value)
            };
            replacements.contains(value)
        }) {
            return Err(Failure::SecretInOutput);
        }
        Ok(())
    }

    pub(super) fn carta(issuer: &str) -> Self {
        let mut redactor = Self::default();
        redactor.selected_issuer = Some(redactor.identifier("issuer", issuer));
        redactor
    }

    pub(super) fn selected_issuer(&self) -> Result<String, Failure> {
        self.selected_issuer
            .map(|id| format!("{}", 1000 + id))
            .ok_or(Failure::Order)
    }

    pub(super) fn body(&mut self, provider: Provider, body: &[u8]) -> Result<Vec<u8>, Failure> {
        if body.len() > super::MAX_BODY {
            return Err(Failure::Bounds);
        }
        let value: Value = crate::json::decode_evidence(body).map_err(|_| Failure::Json)?;
        let mut remaining = 20_000usize;
        let redacted = self.walk(provider, &value, &[], &mut remaining)?;
        serde_json::to_vec_pretty(&redacted).map_err(|_| Failure::Json)
    }

    fn walk(
        &mut self,
        provider: Provider,
        value: &Value,
        path: &[&str],
        remaining: &mut usize,
    ) -> Result<Value, Failure> {
        if path.len() > 32 || *remaining == 0 {
            return Err(Failure::Bounds);
        }
        *remaining -= 1;
        Ok(match value {
            Value::Null | Value::Bool(_) => value.clone(),
            Value::String(s) if s.is_empty() => Value::String(String::new()),
            Value::String(s) => {
                if s.len() > 1_048_576 {
                    return Err(Failure::Bounds);
                }
                Value::String(self.string(provider, s, path)?)
            }
            Value::Number(n) => {
                let key = path.last().copied().unwrap_or_default();
                let usage_count = matches!(
                    path,
                    ["usage", "input_tokens" | "output_tokens" | "total_tokens"]
                        | [
                            "usage",
                            "input_tokens_details",
                            "cached_tokens" | "cache_write_tokens"
                        ]
                        | ["usage", "output_tokens_details", "reasoning_tokens"]
                );
                if (provider == Provider::OpenAi && usage_count)
                    || (provider == Provider::Carta && path == ["expires_in"])
                {
                    if !n.as_u64().is_some_and(|n| n <= 10_000_000) {
                        return Err(Failure::Bounds);
                    }
                    value.clone()
                } else if provider == Provider::OpenAi
                    && path.len() == 1
                    && [
                        "max_output_tokens",
                        "temperature",
                        "top_p",
                        "top_logprobs",
                        "max_tool_calls",
                    ]
                    .contains(&key)
                {
                    if !n.as_f64().is_some_and(|n| (0.0..=1_000_000.0).contains(&n)) {
                        return Err(Failure::Bounds);
                    }
                    value.clone()
                } else if let Some(class) = Self::identifier_class(provider, path) {
                    let identity = if class == "issuer" {
                        n.to_string()
                    } else {
                        format!("number:{n}")
                    };
                    let replacement = 1000 + self.identifier(class, &identity);
                    if n.is_f64() {
                        json!(replacement as f64)
                    } else {
                        json!(replacement)
                    }
                } else if n.is_f64() {
                    json!(0.0)
                } else {
                    json!(0)
                }
            }
            Value::Array(items) => {
                let mut child = path.to_vec();
                child.push("*");
                Value::Array(
                    items
                        .iter()
                        .map(|v| self.walk(provider, v, &child, remaining))
                        .collect::<Result<_, _>>()?,
                )
            }
            Value::Object(object) => {
                let allowed = match provider {
                    Provider::Carta => CARTA_KEYS,
                    Provider::OpenAi => OPENAI_KEYS,
                };
                let mut redacted = Map::new();
                for (key, value) in object {
                    if !allowed.contains(&key.as_str()) {
                        return Err(Failure::UnsupportedField);
                    }
                    let mut child = path.to_vec();
                    child.push(key);
                    redacted.insert(key.clone(), self.walk(provider, value, &child, remaining)?);
                }
                Value::Object(redacted)
            }
        })
    }

    fn string(
        &mut self,
        provider: Provider,
        value: &str,
        path: &[&str],
    ) -> Result<String, Failure> {
        let key = path.last().copied().unwrap_or_default();
        if key == "token_type" {
            return value
                .eq_ignore_ascii_case("bearer")
                .then(|| value.to_owned())
                .ok_or(Failure::UnsupportedLiteral);
        }
        if key == "scope" {
            return value
                .split(' ')
                .all(|s| SCOPES.contains(&s))
                .then(|| value.to_owned())
                .ok_or(Failure::UnsupportedLiteral);
        }
        if provider == Provider::OpenAi {
            let known: Option<&[&str]> = match key {
                "model" => Some(&[super::OPENAI_MODEL]),
                "object" => Some(&["response"]),
                "type" => Some(&[
                    "message",
                    "reasoning",
                    "output_text",
                    "refusal",
                    "summary_text",
                    "reasoning_text",
                    "text",
                ]),
                "role" => Some(&["assistant"]),
                "status" => Some(&[
                    "completed",
                    "incomplete",
                    "failed",
                    "cancelled",
                    "in_progress",
                    "queued",
                ]),
                "service_tier" => Some(&[
                    "default",
                    "auto",
                    "flex",
                    "priority",
                    "scale",
                    "fast",
                    "ultrafast",
                ]),
                "tool_choice" => Some(&["none"]),
                "truncation" => Some(&["disabled", "auto"]),
                "effort" => Some(&["none", "low", "medium", "high", "xhigh", "max"]),
                "verbosity" => Some(&["low", "medium", "high"]),
                "payer" => Some(&["developer", "openai"]),
                "reason" => Some(&["max_output_tokens", "content_filter"]),
                "prompt_cache_retention" => Some(&["in_memory", "24h"]),
                _ => None,
            };
            if let Some(known) = known {
                return known
                    .contains(&value)
                    .then(|| value.to_owned())
                    .ok_or(Failure::UnsupportedLiteral);
            }
        }
        if let Some(class) = Self::identifier_class(provider, path) {
            let identity = if class == "issuer" {
                value.to_owned()
            } else {
                format!("string:{value}")
            };
            let id = self.identifier(class, &identity);
            return Ok(if provider == Provider::OpenAi {
                format!("redacted_{id}")
            } else {
                format!("{}", 1000 + id)
            });
        }
        Ok(match key {
            "access_token" => "EXAMPLE_ACCESS_TOKEN_REDACTED",
            "nextPageToken" => "EXAMPLE_PAGE_TOKEN_REDACTED",
            "email" => "holder@example.test",
            "value" => match path
                .get(path.len().saturating_sub(2))
                .copied()
                .unwrap_or_default()
            {
                "currencyCode" => "USD",
                "quantity"
                | "outstandingQuantity"
                | "vestedQuantity"
                | "exercisedQuantity"
                | "isoQuantity"
                | "nsoQuantity"
                | "maxQuantity"
                | "targetQuantity"
                | "amount" => "0",
                "lastModifiedDatetime" => "2025-01-01T00:00:00Z",
                _ => "2025-01-01",
            },
            _ => "REDACTED",
        }
        .to_owned())
    }

    fn identifier_class(provider: Provider, path: &[&str]) -> Option<&'static str> {
        match path.last().copied().unwrap_or_default() {
            "issuerId" => Some("issuer"),
            "stakeholderId" => Some("stakeholder"),
            "exerciseId" => Some("exercise"),
            "certificateId" => Some("certificate"),
            "id" if provider == Provider::OpenAi => Some("response"),
            "id" if path.contains(&"stakeholders") => Some("stakeholder"),
            "id" if path.contains(&"vestingEvents") => Some("vesting"),
            "id" => Some("grant"),
            _ => None,
        }
    }

    fn identifier(&mut self, class: &str, value: &str) -> u64 {
        let next = self.identifiers.keys().filter(|(c, _)| c == class).count() as u64 + 1;
        *self
            .identifiers
            .entry((class.to_owned(), value.to_owned()))
            .or_insert(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carta_preserves_shape_and_joins_without_private_values() {
        let mut redactor = Redactor::default();
        let people = redactor.body(Provider::Carta, br#"{"stakeholders":[{"id":"private-holder","issuerId":"987654321","fullName":"PRIVATE NAME","email":"private@example.com","employeeId":null,"group":"","address":null}],"nextPageToken":"private-token"}"#).unwrap();
        let grants = redactor.body(Provider::Carta, br#"{"optionGrants":[{"id":"private-grant","issuerId":"987654321","stakeholderId":"private-holder","exercisePrice":{"amount":{"value":"9324.27"}},"isoNsoSplit":false,"exercises":[]}],"nextPageToken":null}"#).unwrap();
        let p: Value = serde_json::from_slice(&people).unwrap();
        let g: Value = serde_json::from_slice(&grants).unwrap();
        assert_eq!(
            p["stakeholders"][0]["id"],
            g["optionGrants"][0]["stakeholderId"]
        );
        assert_eq!(p["stakeholders"][0]["employeeId"], Value::Null);
        assert_eq!(p["stakeholders"][0]["group"], "");
        assert_eq!(g["optionGrants"][0]["isoNsoSplit"], false);
        assert_eq!(g["optionGrants"][0]["exercises"], json!([]));
        assert_eq!(
            g["optionGrants"][0]["exercisePrice"]["amount"]["value"],
            "0"
        );
        assert!(g["nextPageToken"].is_null());
        for bytes in [&people, &grants] {
            let text = std::str::from_utf8(bytes).unwrap();
            for private in [
                "private-holder",
                "private-grant",
                "987654321",
                "PRIVATE NAME",
                "private@example.com",
                "private-token",
                "9324.27",
            ] {
                assert!(!text.contains(private));
            }
        }
    }

    #[test]
    fn duplicate_keys_unknown_keys_and_unreviewed_literals_refuse() {
        for body in [
            br#"{"id":"a","id":"b"}"#.as_slice(),
            br#"{"PRIVATE_NAME":"x"}"#,
            br#"{"model":"private-model"}"#,
        ] {
            assert!(Redactor::default().body(Provider::OpenAi, body).is_err());
        }
    }

    #[test]
    fn openai_keeps_protocol_numbers_and_usage_without_private_text_or_time() {
        let body=br#"{"id":"resp_private","model":"gpt-6-luna","created_at":987654321,"max_output_tokens":64,"temperature":1.0,"top_p":0.9,"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"store":false,"tools":[],"usage":{"input_tokens":8,"output_tokens":64,"total_tokens":72,"output_tokens_details":{"reasoning_tokens":64}},"output":[{"type":"message","content":[{"type":"output_text","text":"PRIVATE NAME private@example.com 9324.27"}]}],"metadata":{}}"#;
        let bytes = Redactor::default().body(Provider::OpenAi, body).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["created_at"], 0);
        assert_eq!(value["max_output_tokens"], 64);
        assert_eq!(value["temperature"], 1.0);
        assert_eq!(value["top_p"], 0.9);
        assert_eq!(value["usage"]["total_tokens"], 72);
        assert_eq!(
            value["usage"]["output_tokens_details"]["reasoning_tokens"],
            64
        );
        assert_eq!(value["incomplete_details"]["reason"], "max_output_tokens");
        assert_eq!(value["metadata"], json!({}));
        let output = std::str::from_utf8(&bytes).unwrap();
        for private in [
            "resp_private",
            "987654321",
            "PRIVATE NAME",
            "private@example.com",
            "9324.27",
        ] {
            assert!(!output.contains(private));
        }
        assert!(
            Redactor::default()
                .body(
                    Provider::OpenAi,
                    br#"{"metadata":{"unreviewed_private_key":"x"}}"#
                )
                .is_err()
        );
        assert!(
            Redactor::default()
                .body(Provider::Carta, &vec![b'x'; super::super::MAX_BODY + 1])
                .is_err()
        );
        let nested = Redactor::default()
            .body(Provider::OpenAi, br#"{"usage":{"id":987654321}}"#)
            .unwrap();
        assert!(!std::str::from_utf8(&nested).unwrap().contains("987654321"));
    }

    #[test]
    fn numeric_identifiers_keep_their_primitive_type_and_distinct_relationships() {
        let mut redactor = Redactor::default();
        let bytes=redactor.body(Provider::Carta,br#"{"stakeholders":[{"id":93247},{"id":83246}],"optionGrants":[{"stakeholderId":93247,"quantity":293840}]}"#).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["stakeholders"][0]["id"].is_number());
        assert_ne!(v["stakeholders"][0]["id"], v["stakeholders"][1]["id"]);
        assert_eq!(
            v["stakeholders"][0]["id"],
            v["optionGrants"][0]["stakeholderId"]
        );
        assert_eq!(v["optionGrants"][0]["quantity"], 0);
    }

    #[test]
    fn selected_child_and_foreign_issuers_are_distinct_and_stable() {
        let mut redactor = Redactor::carta("987654321");
        let people=redactor.body(Provider::Carta,br#"{"stakeholders":[{"issuerId":"987654321"},{"issuerId":"876543210"},{"issuerId":765432109}]}"#).unwrap();
        let grants=redactor.body(Provider::Carta,br#"{"optionGrants":[{"issuerId":"876543210"},{"issuerId":"987654321"},{"issuerId":765432109}]}"#).unwrap();
        let p: Value = serde_json::from_slice(&people).unwrap();
        let g: Value = serde_json::from_slice(&grants).unwrap();
        assert_eq!(
            p["stakeholders"][0]["issuerId"],
            redactor.selected_issuer().unwrap()
        );
        assert_eq!(
            p["stakeholders"][0]["issuerId"],
            g["optionGrants"][1]["issuerId"]
        );
        assert_eq!(
            p["stakeholders"][1]["issuerId"],
            g["optionGrants"][0]["issuerId"]
        );
        assert_eq!(
            p["stakeholders"][2]["issuerId"],
            g["optionGrants"][2]["issuerId"]
        );
        assert_ne!(
            p["stakeholders"][0]["issuerId"],
            p["stakeholders"][1]["issuerId"]
        );
        assert_ne!(
            p["stakeholders"][1]["issuerId"],
            p["stakeholders"][2]["issuerId"]
        );
        assert!(p["stakeholders"][2]["issuerId"].is_number());
        for private in ["987654321", "876543210", "765432109"] {
            assert!(!std::str::from_utf8(&people).unwrap().contains(private));
            assert!(!std::str::from_utf8(&grants).unwrap().contains(private));
        }
    }

    #[test]
    fn all_current_carta_fixture_shapes_are_redactable() {
        for b in [
            include_bytes!("../../fixtures/provider-responses/carta.access_token.json").as_slice(),
            include_bytes!("../../fixtures/provider-responses/carta.stakeholders.json"),
            include_bytes!("../../fixtures/provider-responses/carta.optionGrants.json"),
        ] {
            Redactor::default().body(Provider::Carta, b).unwrap();
        }
    }
}
