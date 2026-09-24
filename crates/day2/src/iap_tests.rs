use super::*;
use crate::error::{Failure, classify};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const AUDIENCE: &str = "/projects/123/global/backendServices/456";
const NOW: i64 = 1_800_000_000;

struct Signer {
    kid: String,
    pair: EcdsaKeyPair,
}

impl Signer {
    fn new(kid: &str) -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            kid: kid.to_owned(),
            pair,
        }
    }

    fn jwk(&self) -> Value {
        let point = self.pair.public_key().as_ref();
        json!({
            "kid": self.kid, "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
        })
    }

    fn sign_with(&self, header: Value, claims: Value) -> String {
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let signature = self
            .pair
            .sign(&SystemRandom::new(), signed.as_bytes())
            .unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    fn sign(&self, claims: Value) -> String {
        self.sign_with(
            json!({"alg": "ES256", "kid": self.kid, "typ": "JWT"}),
            claims,
        )
    }
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": NOW - 10,
        "exp": NOW + 590,
        "sub": "accounts.google.com:1234567890",
        "email": "Ada@Example.com",
        "hd": "example.com",
    })
}

fn with(changes: Value) -> Value {
    let mut claims = claims();
    for (key, value) in changes.as_object().unwrap() {
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(key);
        } else {
            claims[key] = value.clone();
        }
    }
    claims
}

/// A key source that serves whatever the test last published and counts how
/// often it was asked.
#[derive(Clone, Default)]
struct Keys {
    published: Arc<Mutex<Option<String>>>,
    fetches: Arc<AtomicUsize>,
}

impl Keys {
    fn publish(&self, signers: &[&Signer]) {
        let keys: Vec<Value> = signers.iter().map(|s| s.jwk()).collect();
        *self.published.lock().unwrap() = Some(json!({"keys": keys}).to_string());
    }
    fn outage(&self) {
        *self.published.lock().unwrap() = None;
    }
    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

impl KeySource for Keys {
    fn fetch(&self) -> Result<String> {
        self.fetches.fetch_add(1, Ordering::SeqCst);
        self.published
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| anyhow::anyhow!("unreachable"))
    }
}

fn verifier(keys: &Keys) -> Verifier {
    Verifier::new(AUDIENCE, "example.com", Box::new(keys.clone())).unwrap()
}

fn setup() -> (Signer, Keys, Verifier) {
    let signer = Signer::new("k1");
    let keys = Keys::default();
    keys.publish(&[&signer]);
    let verifier = verifier(&keys);
    (signer, keys, verifier)
}

fn refused(result: Result<Verified>) -> Failure {
    classify(&result.expect_err("assertion should be refused"))
}

#[test]
fn a_genuine_assertion_names_the_lowercased_email_and_the_subject() {
    let (signer, _, verifier) = setup();
    let verified = verifier.verify(&signer.sign(claims()), NOW).unwrap();
    assert_eq!(
        verified,
        Verified {
            email: "ada@example.com".into(),
            subject: "accounts.google.com:1234567890".into(),
        }
    );
}

#[test]
fn every_claim_check_refuses_with_the_same_code() {
    let (signer, _, verifier) = setup();
    let cases = [
        (
            "wrong issuer",
            with(json!({"iss": "https://accounts.google.com"})),
        ),
        (
            "another app's audience",
            with(json!({"aud": "/projects/123/global/backendServices/999"})),
        ),
        (
            "expired beyond skew",
            with(json!({"exp": NOW - CLOCK_SKEW - 1})),
        ),
        ("no subject", with(json!({"sub": " "}))),
        ("no email", with(json!({"email": ""}))),
        ("not an address", with(json!({"email": "ada"}))),
        (
            "other hosted domain",
            with(json!({"hd": "other.example.com", "email": "ada@other.example.com"})),
        ),
        ("no hosted domain", with(json!({"hd": null}))),
        // A consumer account can be added to an IAP access list by mistake;
        // `hd` saying our domain while the address does not is refused too.
        (
            "address outside the domain",
            with(json!({"email": "ada@gmail.com"})),
        ),
        ("missing expiry", with(json!({"exp": null}))),
    ];
    for (name, claims) in cases {
        assert_eq!(
            refused(verifier.verify(&signer.sign(claims), NOW)),
            Failure::InvalidIdentityAssertion,
            "{name}"
        );
    }
}

#[test]
fn expiry_tolerates_the_clock_skew_and_no_more() {
    let (signer, _, verifier) = setup();
    let at_edge = signer.sign(with(json!({"exp": NOW - CLOCK_SKEW})));
    assert!(verifier.verify(&at_edge, NOW).is_ok());
    let past = signer.sign(with(json!({"exp": NOW - CLOCK_SKEW - 1})));
    assert_eq!(
        refused(verifier.verify(&past, NOW)),
        Failure::InvalidIdentityAssertion
    );
}

#[test]
fn a_hosted_domain_differing_only_in_case_is_the_same_domain() {
    let (signer, _, verifier) = setup();
    let assertion = signer.sign(with(json!({"hd": "Example.COM"})));
    assert_eq!(
        verifier.verify(&assertion, NOW).unwrap().email,
        "ada@example.com"
    );
}

#[test]
fn a_service_account_is_sent_to_the_delegation_protocol() {
    let (signer, _, verifier) = setup();
    let assertion = signer.sign(with(json!({
        "email": "control-plane@exampleco-tools.iam.gserviceaccount.com"
    })));
    assert_eq!(
        refused(verifier.verify(&assertion, NOW)),
        Failure::MachineCallerRequiresDelegation
    );
}

#[test]
fn the_signature_must_come_from_a_published_key() {
    let (signer, _, verifier) = setup();
    // Same key id, different key: exactly what a forger can produce.
    let forger = Signer::new("k1");
    assert_eq!(
        refused(verifier.verify(&forger.sign(claims()), NOW)),
        Failure::InvalidIdentityAssertion
    );

    // A genuine signature over different claims.
    let genuine = signer.sign(claims());
    let parts: Vec<&str> = genuine.split('.').collect();
    let elevated = URL_SAFE_NO_PAD.encode(with(json!({"email": "root@example.com"})).to_string());
    let spliced = format!("{}.{elevated}.{}", parts[0], parts[2]);
    assert_eq!(
        refused(verifier.verify(&spliced, NOW)),
        Failure::InvalidIdentityAssertion
    );
}

#[test]
fn only_es256_is_accepted() {
    let (signer, _, verifier) = setup();
    for alg in ["none", "HS256", "RS256", "ES384", "es256"] {
        let assertion = signer.sign_with(json!({"alg": alg, "kid": "k1"}), claims());
        assert_eq!(
            refused(verifier.verify(&assertion, NOW)),
            Failure::InvalidIdentityAssertion,
            "{alg}"
        );
    }
    let unsigned = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(json!({"alg": "none", "kid": "k1"}).to_string()),
        URL_SAFE_NO_PAD.encode(claims().to_string())
    );
    assert_eq!(
        refused(verifier.verify(&unsigned, NOW)),
        Failure::InvalidIdentityAssertion
    );
}

#[test]
fn malformed_assertions_are_refused_without_fetching_keys() {
    let (signer, keys, verifier) = setup();
    let genuine = signer.sign(claims());
    let oversized = "a".repeat(MAX_ASSERTION_BYTES + 1);
    for assertion in [
        "",
        "one",
        "one.two",
        &format!("{genuine}.extra"),
        "!!!.!!!.!!!",
        oversized.as_str(),
    ] {
        assert_eq!(
            refused(verifier.verify(assertion, NOW)),
            Failure::InvalidIdentityAssertion
        );
    }
    assert_eq!(keys.fetches(), 0);
}

#[test]
fn keys_are_cached_for_their_lifetime_then_refetched() {
    let (signer, keys, verifier) = setup();
    let assertion = signer.sign(with(json!({"exp": NOW + 10 * KEY_LIFETIME})));
    for offset in [0, 1, KEY_LIFETIME - 1] {
        verifier.verify(&assertion, NOW + offset).unwrap();
    }
    assert_eq!(keys.fetches(), 1);
    verifier.verify(&assertion, NOW + KEY_LIFETIME).unwrap();
    assert_eq!(keys.fetches(), 2);
}

#[test]
fn a_rotated_key_is_picked_up_without_waiting_out_the_cache() {
    let (old, keys, verifier) = setup();
    verifier.verify(&old.sign(claims()), NOW).unwrap();

    let new = Signer::new("k2");
    keys.publish(&[&old, &new]);
    verifier
        .verify(&new.sign(claims()), NOW + REFRESH_FLOOR)
        .unwrap();
    assert_eq!(keys.fetches(), 2);
}

#[test]
fn invented_key_ids_cannot_drive_fetches_faster_than_the_floor() {
    let (signer, keys, verifier) = setup();
    verifier.verify(&signer.sign(claims()), NOW).unwrap();
    for (n, offset) in (0..20).zip(0..) {
        let stranger = Signer::new(&format!("invented-{n}"));
        assert_eq!(
            refused(verifier.verify(&stranger.sign(claims()), NOW + offset)),
            Failure::InvalidIdentityAssertion
        );
    }
    assert_eq!(
        keys.fetches(),
        1,
        "within the floor, unknown ids do not fetch"
    );
    let stranger = Signer::new("invented-late");
    let _ = verifier.verify(&stranger.sign(claims()), NOW + REFRESH_FLOOR);
    assert_eq!(keys.fetches(), 2);
    // A known key still verifies throughout.
    verifier
        .verify(&signer.sign(claims()), NOW + REFRESH_FLOOR)
        .unwrap();
}

#[test]
fn with_no_keys_an_outage_fails_closed_and_says_so() {
    let (signer, keys, verifier) = setup();
    keys.outage();
    assert_eq!(
        refused(verifier.verify(&signer.sign(claims()), NOW)),
        Failure::IdentityKeysUnavailable
    );
}

#[test]
fn with_stale_keys_an_outage_keeps_verifying_known_keys() {
    let (signer, keys, verifier) = setup();
    let assertion = signer.sign(with(json!({"exp": NOW + 10 * KEY_LIFETIME})));
    verifier.verify(&assertion, NOW).unwrap();
    keys.outage();
    verifier.verify(&assertion, NOW + 2 * KEY_LIFETIME).unwrap();
    assert_eq!(
        keys.fetches(),
        2,
        "the stale set was due and a refresh was tried"
    );
}

#[test]
fn key_sets_without_usable_keys_are_not_keys() {
    let rsa = json!({"keys": [{"kid": "r", "kty": "RSA", "n": "AQAB", "e": "AQAB"}]});
    assert!(parse_keys(&rsa.to_string()).is_err());
    let short = json!({"keys": [{"kid": "s", "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}]});
    assert!(parse_keys(&short.to_string()).is_err());
    assert!(parse_keys("{}").is_err());
}

#[test]
fn a_verifier_needs_an_audience_and_a_domain() {
    let keys = Keys::default();
    assert!(Verifier::new("", "example.com", Box::new(keys.clone())).is_err());
    assert!(Verifier::new(AUDIENCE, " ", Box::new(keys)).is_err());
}

#[test]
fn an_address_stays_with_the_first_account_seen_for_it() {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(crate::audit::PRINCIPALS_DDL).unwrap();
    let original = Verified {
        email: "ada@example.com".into(),
        subject: "accounts.google.com:1".into(),
    };
    bind_subject(&db, &original, NOW).unwrap();
    bind_subject(&db, &original, NOW + 1).unwrap();

    // The same address, reassigned to a new account.
    let successor = Verified {
        subject: "accounts.google.com:2".into(),
        ..original.clone()
    };
    assert_eq!(
        classify(&bind_subject(&db, &successor, NOW + 2).unwrap_err()),
        Failure::PrincipalSubjectChanged
    );
    // Refusing the successor changed nothing for the original.
    bind_subject(&db, &original, NOW + 3).unwrap();
    let first_seen: i64 = db
        .query_row(
            "SELECT first_seen FROM day2_principals WHERE email='ada@example.com'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(first_seen, NOW);

    // Other addresses are bound independently.
    bind_subject(
        &db,
        &Verified {
            email: "grace@example.com".into(),
            subject: "accounts.google.com:2".into(),
        },
        NOW,
    )
    .unwrap();
}

#[test]
fn a_genuine_assertion_over_the_size_bound_is_refused_unread() {
    let (signer, keys, verifier) = setup();
    let padded = signer.sign(with(json!({"padding": "x".repeat(MAX_ASSERTION_BYTES)})));
    assert!(padded.len() > MAX_ASSERTION_BYTES);
    assert_eq!(
        refused(verifier.verify(&padded, NOW)),
        Failure::InvalidIdentityAssertion
    );
    assert_eq!(keys.fetches(), 0, "refused before any key was looked up");
}
