use super::*;

const ACCOUNT: &str = "reader@project.iam.gserviceaccount.com";
const SCOPES: [&str; 2] = ["scope-a", "scope-b"];

/// Answers each exchange from a fixed script and records what was sent.
struct Scripted {
    replies: Vec<std::result::Result<Reply, Unreached>>,
    sent: Vec<String>,
}

fn json(status: u16, body: serde_json::Value) -> std::result::Result<Reply, Unreached> {
    Ok(Reply {
        status,
        metadata_flavor: false,
        json: true,
        body: body.to_string().into_bytes(),
        retry_after_seconds: None,
    })
}

fn metadata() -> std::result::Result<Reply, Unreached> {
    Ok(Reply {
        metadata_flavor: true,
        ..json(
            200,
            serde_json::json!({"access_token":"workload","token_type":"Bearer","expires_in":3600}),
        )?
    })
}

fn signed(claims: &str, kid: &str, signature: usize) -> String {
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    format!(
        "{}.{}.{}",
        encode(format!(r#"{{"alg":"RS256","kid":"{kid}"}}"#).as_bytes()),
        encode(claims.as_bytes()),
        encode(&vec![7u8; signature])
    )
}

impl TokenWire for Scripted {
    fn exchange(
        &mut self,
        exchange: &Exchange<'_>,
        max_bytes: usize,
    ) -> std::result::Result<Reply, Unreached> {
        assert_eq!(max_bytes, MAX_EXCHANGE_RESPONSE_BYTES);
        self.sent.push(match exchange {
            Exchange::Metadata => "metadata".into(),
            Exchange::Iam {
                service_account,
                method,
                bearer,
                body,
            } => format!(
                "iam {service_account}:{} {} {}",
                method.name(),
                bearer.bearer(),
                String::from_utf8_lossy(body)
            ),
            Exchange::Token { form } => format!("token {form}"),
        });
        assert!(!self.replies.is_empty(), "an unscripted exchange was sent");
        self.replies.remove(0)
    }
}

fn run(
    identity: Identity<'_>,
    replies: Vec<std::result::Result<Reply, Unreached>>,
) -> (Result<String, Failure>, Vec<String>) {
    let mut wire = Scripted {
        replies,
        sent: Vec::new(),
    };
    let result = acquire(
        &mut wire,
        &TokenRequest {
            service_account: ACCOUNT,
            identity,
            scopes: &SCOPES,
        },
        100,
    )
    .map(|token| token.bearer().to_owned());
    (result, wire.sent)
}

#[test]
fn iam_response_cannot_change_the_selected_authentication_flow() {
    let direct = IamToken {
        access_token: Some("token".into()),
        signed_jwt: None,
        key_id: None,
    };
    assert!(validate_iam_token_shape(&direct, false).is_ok());
    assert!(validate_iam_token_shape(&direct, true).is_err());
    let delegated = IamToken {
        access_token: None,
        signed_jwt: Some("a.b.c".into()),
        key_id: Some("key".into()),
    };
    assert!(validate_iam_token_shape(&delegated, true).is_ok());
    assert!(validate_iam_token_shape(&delegated, false).is_err());
}

#[test]
fn a_direct_token_is_minted_by_generate_access_token_with_exactly_the_action_scopes() {
    let (result, sent) = run(
        Identity::ServiceAccount,
        vec![
            metadata(),
            json(
                200,
                serde_json::json!({"accessToken":"minted","expireTime":"2030-01-01T00:00:00Z"}),
            ),
        ],
    );
    assert_eq!(result, Ok("minted".into()));
    assert_eq!(
        sent,
        [
            "metadata".to_owned(),
            format!(
                r#"iam {ACCOUNT}:generateAccessToken workload {{"lifetime":"3600s","scope":["scope-a","scope-b"]}}"#
            ),
        ]
    );
}

#[test]
fn a_delegated_token_signs_exactly_the_planned_claims_and_exchanges_them() -> anyhow::Result<()> {
    let claims = delegated_claims(ACCOUNT, "person@example.com", &SCOPES, 100)
        .map_err(|failure| anyhow::anyhow!("{failure:?}"))?;
    let jwt = signed(&claims, "kid-1", 64);
    let (result, sent) = run(
        Identity::Delegated("person@example.com"),
        vec![
            metadata(),
            json(200, serde_json::json!({"keyId":"kid-1","signedJwt":jwt})),
            json(
                200,
                serde_json::json!({"access_token":"delegated","token_type":"Bearer","expires_in":3600}),
            ),
        ],
    );
    assert_eq!(result, Ok("delegated".into()));
    assert_eq!(sent.len(), 3);
    assert!(sent[1].starts_with(&format!("iam {ACCOUNT}:signJwt workload ")));
    let body: serde_json::Value = serde_json::from_str(sent[1].splitn(4, ' ').nth(3).unwrap())?;
    let signed_claims: serde_json::Value = serde_json::from_str(body["payload"].as_str().unwrap())?;
    assert_eq!(
        signed_claims,
        serde_json::json!({"iss":ACCOUNT,"sub":"person@example.com",
            "aud":GOOGLE_TOKEN_ENDPOINT,"iat":100,"exp":400,"scope":"scope-a scope-b"})
    );
    assert_eq!(sent[2], format!("token {}", assertion_form(&jwt)));
    assert!(sent[2].contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"));
    Ok(())
}

#[test]
fn a_signed_jwt_that_widens_or_changes_the_plan_is_never_exchanged() -> anyhow::Result<()> {
    let subject = "person@example.com";
    let claims = |sub: &str, scope: &str, exp: i64| {
        serde_json::json!({"iss":ACCOUNT,"sub":sub,"aud":GOOGLE_TOKEN_ENDPOINT,
            "iat":100,"exp":exp,"scope":scope})
        .to_string()
    };
    let cases = [
        signed(
            &claims("other@example.com", "scope-a scope-b", 400),
            "kid-1",
            64,
        ),
        signed(
            &claims(subject, "scope-a scope-b scope-c", 400),
            "kid-1",
            64,
        ),
        signed(&claims(subject, "scope-a scope-b", 3700), "kid-1", 64),
        signed(&claims(subject, "scope-a scope-b", 400), "other-kid", 64),
        signed(&claims(subject, "scope-a scope-b", 400), "kid-1", 16),
        "not-a-jwt".into(),
    ];
    for jwt in cases {
        let (result, sent) = run(
            Identity::Delegated(subject),
            vec![
                metadata(),
                json(200, serde_json::json!({"keyId":"kid-1","signedJwt":jwt})),
            ],
        );
        assert_eq!(result, Err(Failure::AuthenticationFailed));
        assert_eq!(
            sent.len(),
            2,
            "a rejected assertion reached the token endpoint"
        );
    }
    Ok(())
}

#[test]
fn workload_identity_failures_stop_before_iam() {
    let not_flavored = json(
        200,
        serde_json::json!({"access_token":"workload","token_type":"Bearer"}),
    );
    for reply in [
        Err(Unreached::default()),
        not_flavored,
        Ok(Reply {
            status: 500,
            ..metadata().unwrap()
        }),
        Ok(Reply {
            body: br#"{"access_token":"workload","token_type":"Basic"}"#.to_vec(),
            ..metadata().unwrap()
        }),
        Ok(Reply {
            body: vec![b' '; MAX_EXCHANGE_RESPONSE_BYTES + 1],
            ..metadata().unwrap()
        }),
    ] {
        let (result, sent) = run(Identity::ServiceAccount, vec![reply]);
        assert_eq!(result, Err(Failure::WorkloadIdentityUnavailable));
        assert_eq!(sent, ["metadata"]);
    }
}

#[test]
fn iam_and_token_endpoint_replies_are_classified_without_provider_content() {
    let direct = |reply| run(Identity::ServiceAccount, vec![metadata(), reply]).0;
    assert_eq!(
        direct(json(429, serde_json::json!({}))),
        Err(Failure::RateLimited)
    );
    assert_eq!(
        direct(json(503, serde_json::json!({}))),
        Err(Failure::Unavailable)
    );
    assert_eq!(
        direct(json(403, serde_json::json!({"error":"denied"}))),
        Err(Failure::AuthenticationFailed)
    );
    assert_eq!(direct(Err(Unreached::default())), Err(Failure::Unavailable));
    assert_eq!(
        direct(Err(Unreached {
            too_large: true,
            ..Unreached::default()
        })),
        Err(Failure::ResponseTooLarge)
    );
    assert_eq!(
        direct(Ok(Reply {
            body: vec![b' '; MAX_EXCHANGE_RESPONSE_BYTES + 1],
            ..json(200, serde_json::json!({})).unwrap()
        })),
        Err(Failure::ResponseTooLarge)
    );
    // A delegated plan answered with a direct token is refused.
    assert_eq!(
        direct(json(
            200,
            serde_json::json!({"keyId":"kid","signedJwt":"a.b.c"})
        )),
        Err(Failure::AuthenticationFailed)
    );
    assert_eq!(
        direct(json(200, serde_json::json!({"accessToken":"bad token"}))),
        Err(Failure::AuthenticationFailed)
    );
    let claims = delegated_claims(ACCOUNT, "person@example.com", &SCOPES, 100).unwrap();
    let delegated = |reply| {
        run(
            Identity::Delegated("person@example.com"),
            vec![
                metadata(),
                json(
                    200,
                    serde_json::json!({"keyId":"kid-1","signedJwt":signed(&claims, "kid-1", 64)}),
                ),
                reply,
            ],
        )
        .0
    };
    // The delegation client is not authorized for a scope, or the subject is
    // not a user: Google refuses at the token endpoint.
    assert_eq!(
        delegated(json(
            400,
            serde_json::json!({"error":"unauthorized_client"})
        )),
        Err(Failure::AuthenticationFailed)
    );
    assert_eq!(
        delegated(json(
            200,
            serde_json::json!({"access_token":"t","token_type":"MAC"})
        )),
        Err(Failure::AuthenticationFailed)
    );
    assert_eq!(
        delegated(json(429, serde_json::json!({}))),
        Err(Failure::RateLimited)
    );
}

#[test]
fn every_exchange_counts_only_its_posted_body() {
    let workload = WorkloadToken("w".into());
    assert_eq!(Exchange::Metadata.request_bytes(), 0);
    assert_eq!(
        Exchange::Iam {
            service_account: ACCOUNT,
            method: IamMethod::SignJwt,
            bearer: &workload,
            body: b"12345",
        }
        .request_bytes(),
        5
    );
    assert_eq!(Exchange::Token { form: "abc" }.request_bytes(), 3);
}
