//! Ramp Funds API, POST /developer/v1/funds, with a prior business identity read.
//! https://docs.ramp.com/openapi/developer-api.json
use crate::integrations::transport::{Method, WireRequest, WireResponse};
use crate::integrations::{AdapterError, PreparedCall, ResponseProfile};
use day2_capabilities::integrations::{LiveConnection, RampFundPolicy, RampInterval, ramp_uuid};
use serde::Deserialize;
use serde_json::{Value, json};

pub(super) const BUSINESS: &str = "https://api.ramp.com/developer/v1/business";
pub(super) const FUNDS: &str = "https://api.ramp.com/developer/v1/funds";

// The Funds API needs only the business ID. A typed projection rejects missing
// or duplicate IDs and discards the rest of the business profile.
#[derive(Deserialize)]
pub(super) struct Business {
    pub(super) id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    handle: String,
    amount_cents: u64,
    interval: RampInterval,
}

pub(super) fn identity() -> WireRequest {
    WireRequest {
        method: Method::Get,
        url: BUSINESS.into(),
        headers: vec![],
        body: vec![],
    }
}
pub(super) fn prepare(
    connection: &LiveConnection,
    policy: &RampFundPolicy,
    input: &str,
) -> Result<PreparedCall, AdapterError> {
    let request: Request =
        crate::json::decode(input.as_bytes()).map_err(|_| AdapterError::InvalidRequest)?;
    if request.handle.is_empty()
        || request.amount_cents == 0
        || request.amount_cents > policy.max_amount_cents
        || request.interval != policy.interval
    {
        return Err(AdapterError::InvalidRequest);
    }
    let body = json!({
        "display_name":"Day2 vendor spend",
        "user_id": policy.owner_id,
        "is_shareable":false,
        "is_exempt_from_policy_agent":false,
        "permitted_spend_types":{"physical_card":false,"reimbursements":false,"virtual_card":true},
        "spending_restrictions":{
            "allowed_vendor_ids":[policy.merchant_id],
            "interval":request.interval,
            "limit":{"amount":request.amount_cents,"currency_code":"USD"}
        }
    });
    Ok(PreparedCall {
        connection: connection.clone(),
        request: WireRequest::json(FUNDS, body.to_string().into_bytes()),
        response: ResponseProfile::RampFund {
            policy: policy.clone(),
            amount_cents: request.amount_cents,
        },
        response_limit: 0,
        reserved_monetary_microusd: Some(0),
    })
}

// The successful POST returns a Fund. Verify the restriction actually in force.
// Sensitive provider fields, including card details, never enter the operation result.
pub(super) fn response(
    response: &WireResponse,
    policy: &RampFundPolicy,
    cents: u64,
) -> (Result<String, AdapterError>, bool) {
    let error = match response.status {
        400 | 401 | 403 | 404 => return (Err(AdapterError::ProviderDenied), false),
        429 => return (Err(AdapterError::RateLimited), false),
        201 if response.json_content_type => None,
        201 => Some(AdapterError::ResponseInvalid),
        _ => Some(AdapterError::Incomplete),
    };
    if let Some(error) = error {
        return (Err(error), true);
    }
    let result = crate::json::decode::<Value>(&response.body)
        .ok().and_then(|fund| {
            let id = fund.get("id")?.as_str()?;
            let members = fund.get("members")?.as_array()?;
            let restrictions = fund.get("spending_restrictions")?;
            let valid = ramp_uuid(id) && fund.get("state")?.as_str()? == "ACTIVE"
                && fund.get("suspension")?.is_null() && fund.get("spend_program_id")?.is_null()
                && !fund.get("is_shareable")?.as_bool()?
                && !fund.get("is_exempt_from_policy_agent")?.as_bool()?
                && members.len() == 1 && members[0].get("user_id")?.as_str()? == policy.owner_id
                && members[0].get("suspension")?.is_null()
                && fund.get("permitted_spend_types")? == &json!({"virtual_card_enabled":true,"physical_card_enabled":false,"reimbursements_enabled":false})
                && restrictions.get("allowed_vendor_ids")? == &json!([policy.merchant_id])
                && restrictions.get("limit")? == &json!({"amount":cents,"currency_code":"USD"})
                && restrictions.get("interval")? == &json!(policy.interval)
                && restrictions.get("temporary_limit")?.is_null();
            valid.then(|| json!({"fund_id":id}).to_string())
        }).ok_or(AdapterError::ResponseInvalid);
    let unknown = result.is_err();
    (result, unknown)
}
