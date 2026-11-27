use super::*;
use day2_capabilities::integrations::{RampFundPolicy, RampInterval};

fn profile() -> RampFundPolicy {
    RampFundPolicy {
        owner_id: RAMP_OWNER.into(),
        merchant_id: RAMP_MERCHANT.into(),
        max_amount_cents: 5000,
        interval: RampInterval::Monthly,
    }
}

fn call(
    business: &str,
    profile: RampFundPolicy,
    data: Value,
) -> Result<PreparedCall, AdapterError> {
    prepare(
        &Action::RampCreateFund,
        &LiveConnection::Ramp {
            credential_ref: reference(),
            business_id: business.into(),
        },
        &ResourceTarget::RampFundPolicy { profile },
        &data.to_string(),
        2048,
        16384,
    )
}

fn input(cents: u64) -> Value {
    json!({"handle":"signed-handle","amount_cents":cents,"interval":"MONTHLY"})
}

#[test]
fn funded_amount_merchant_owner_interval_and_business_bound_each_attempt() -> Result<()> {
    let fixture = Fixture::new()?;
    for data in [
        input(0),
        input(5001),
        json!({"handle":"signed","amount_cents":5000,"interval":"TOTAL"}),
        json!({"handle":"signed","amount_cents":5000,"interval":"MONTHLY","user_id":RAMP_OWNER}),
        json!({"handle":"signed","amount_cents":5000,"interval":"MONTHLY","allowed_vendor_ids":[]}),
    ] {
        assert!(matches!(
            call(RAMP_BUSINESS, profile(), data),
            Err(AdapterError::InvalidRequest)
        ));
    }
    let foreign = fixture.run(&call(RAMP_OWNER, profile(), input(1))?);
    assert!(matches!(foreign.result, Err(AdapterError::ProviderDenied)));
    assert_eq!(foreign.calls, 1);
    let valid = call(RAMP_BUSINESS, profile(), input(5000))?;
    fixture.schedule_on(RAMP_WORLD, "business", SimulatedFault::ReplyLost)?;
    let unidentified = fixture.run(&valid);
    assert!(unidentified.result.is_err() && !unidentified.outcome_unknown);
    assert_eq!(unidentified.calls, 1);
    update_ramp(&fixture.database, SCOPE, |world| {
        assert!(world.world.funds.is_empty());
        Ok(())
    })?;
    let result = fixture.run(&valid);
    assert_eq!(result.calls, 2);
    assert!(!result.outcome_unknown);
    let id: Value = serde_json::from_str(&result.result?)?;
    assert_eq!(id.as_object().unwrap().len(), 1);
    assert!(day2_capabilities::integrations::ramp_uuid(
        id["fund_id"].as_str().unwrap()
    ));
    update_ramp(&fixture.database, SCOPE, |world| {
        assert_eq!(world.world.funds.len(), 1);
        let fund = world.world.funds.values().next().unwrap();
        assert_eq!(fund.id, id["fund_id"]);
        assert_eq!(fund.owner_id, RAMP_OWNER);
        assert_eq!(fund.merchant_id, RAMP_MERCHANT);
        assert_eq!(fund.amount_cents, 5000);
        assert_eq!(fund.interval, "MONTHLY");
        Ok(())
    })
}

#[test]
fn deterministic_lost_reply_commits_once_and_cannot_claim_success() -> Result<()> {
    let fixture = Fixture::new()?;
    fixture.schedule_on(RAMP_WORLD, "funds.create", SimulatedFault::ReplyLost)?;
    let request = call(RAMP_BUSINESS, profile(), input(100))?;
    let lost = fixture.run(&request);
    assert!(lost.outcome_unknown);
    assert!(matches!(
        lost.result,
        Err(AdapterError::TransportUnavailable)
    ));
    update_ramp(&fixture.database, SCOPE, |world| {
        assert_eq!(world.calls, ["business", "funds.create"]);
        assert_eq!(world.world.funds.len(), 1);
        Ok(())
    })?;
    // Wire simulator models same-key redelivery within this scenario. Runtime
    // refuses a second dispatch after an uncertain write.
    let same_key = fixture.run(&request);
    assert!(same_key.result.is_ok());
    let changed = fixture.run(&call(RAMP_BUSINESS, profile(), input(99))?);
    assert!(changed.outcome_unknown);
    assert!(changed.result.is_err());
    update_ramp(&fixture.database, SCOPE, |world| {
        assert_eq!(world.world.funds.len(), 1);
        Ok(())
    })
}

#[test]
fn changed_or_unrestricted_success_responses_require_reconciliation() {
    let valid = json!({"id":"33333333-0000-4000-8000-000000000001","state":"ACTIVE","suspension":null,
        "spend_program_id":null,"is_shareable":false,"is_exempt_from_policy_agent":false,
        "members":[{"user_id":RAMP_OWNER,"suspension":null}],
        "permitted_spend_types":{"physical_card_enabled":false,"reimbursements_enabled":false,"virtual_card_enabled":true},
        "spending_restrictions":{"allowed_vendor_ids":[RAMP_MERCHANT],"interval":"MONTHLY",
            "temporary_limit":null,"limit":{"amount":99,"currency_code":"USD"}}
    });
    for (field, value) in [
        ("/spending_restrictions/allowed_vendor_ids", Value::Null),
        ("/spending_restrictions/limit/amount", json!(100)),
        ("/members/0/user_id", json!(RAMP_MERCHANT)),
        ("/permitted_spend_types/physical_card_enabled", json!(true)),
        ("/spending_restrictions/temporary_limit", json!(200)),
    ] {
        let mut fund = valid.clone();
        *fund.pointer_mut(field).unwrap() = value;
        let mut reply = json_response(&fund);
        reply.status = 201;
        let (result, unknown) = crate::integrations::ramp::response(&reply, &profile(), 99);
        assert!(
            unknown && matches!(result, Err(AdapterError::ResponseInvalid)),
            "{field}"
        );
    }
}

#[test]
fn attenuation_can_lower_only_the_amount_for_the_same_fund_policy() {
    let original = profile();
    let target = |profile| ResourceTarget::RampFundPolicy { profile };
    let parent = target(original.clone());
    assert!(
        target(RampFundPolicy {
            max_amount_cents: 1,
            ..original.clone()
        })
        .is_subset_of(&parent)
    );
    for other in [
        RampFundPolicy {
            owner_id: RAMP_MERCHANT.into(),
            ..original.clone()
        },
        RampFundPolicy {
            merchant_id: RAMP_OWNER.into(),
            ..original.clone()
        },
        RampFundPolicy {
            max_amount_cents: 5001,
            ..original.clone()
        },
        RampFundPolicy {
            interval: RampInterval::Total,
            ..original.clone()
        },
    ] {
        assert!(!target(other).is_subset_of(&parent));
    }
}

#[test]
fn duplicate_identity_fields_cannot_select_a_business() {
    use crate::integrations::{decode_http_json, ramp::Business};
    let mut reply = json_response(&json!({"id":RAMP_BUSINESS}));
    reply.body = format!(r#"{{"id":"{RAMP_OWNER}","id":"{RAMP_BUSINESS}"}}"#).into_bytes();
    assert!(matches!(
        decode_http_json::<Business>(&reply),
        Err(AdapterError::ResponseInvalid)
    ));
}
