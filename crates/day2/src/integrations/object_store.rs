//! Any S3-compatible object store: real S3, GCS through its XML API, R2, MinIO.
//!
//! The application never holds an object's bytes. Three of the four operations are
//! ordinary signed requests; the two `grant` operations return a **presigned URL**
//! that a client uses to transfer directly to the store. That is what keeps a
//! 300-MiB upload away from a 64-KiB observation, and it means the platform is
//! never on the data path — it authorizes transfers rather than performing them.
//!
//! Signing is AWS Signature Version 4, which every compatible vendor implements;
//! GCS accepts it against `storage.googleapis.com` with HMAC keys.

use super::AdapterError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// How long a granted authorization is valid. Short by design: a presigned URL is
/// a bearer capability for one object, and the window is the whole of its
/// containment. Long enough for a large transfer to start, not to be filed away.
pub(crate) const GRANT_SECONDS: u64 = 900;

pub(crate) struct Signer<'a> {
    pub(crate) access_key_id: &'a str,
    pub(crate) secret: &'a str,
    pub(crate) region: &'a str,
}

/// `YYYYMMDD'T'HHMMSS'Z'` and its date prefix, from a Unix timestamp.
///
/// Written out rather than pulled from a date library because the format is part
/// of the signature: a differing rendering is a differing string to sign, and a
/// dependency's idea of "ISO 8601" is not necessarily AWS's.
pub(crate) fn timestamps(now: i64) -> (String, String) {
    let days = now.div_euclid(86_400);
    let seconds = now.rem_euclid(86_400);
    // Civil-from-days, Howard Hinnant's algorithm: exact for the whole range and
    // free of the leap-year edge cases a hand-rolled version gets wrong.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    let date = format!("{year:04}{month:02}{day:02}");
    let stamp = format!(
        "{date}T{:02}{:02}{:02}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    );
    (stamp, date)
}

fn hmac(key: &[u8], message: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Percent-encoding for S3 canonical requests: unreserved characters pass, and
/// `/` survives in a path but not in a query value.
fn encode(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let plain = byte.is_ascii_alphanumeric() || b"-._~".contains(&byte);
        if plain || (keep_slash && byte == b'/') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Signer<'_> {
    fn signing_key(&self, date: &str) -> Vec<u8> {
        let key = hmac(format!("AWS4{}", self.secret).as_bytes(), date);
        let key = hmac(&key, self.region);
        let key = hmac(&key, "s3");
        hmac(&key, "aws4_request")
    }

    /// A presigned URL authorizing exactly one method on exactly one object.
    ///
    /// The signature covers the method, the key, the expiry and the host, so the
    /// holder cannot retarget it: changing any of them invalidates it. That is the
    /// property that makes handing one to a browser safe.
    pub(crate) fn presign(
        &self,
        method: &str,
        endpoint: &str,
        bucket: &str,
        key: &str,
        expires: u64,
        now: i64,
    ) -> Result<String, AdapterError> {
        let host = endpoint
            .strip_prefix("https://")
            .ok_or(AdapterError::ResponseInvalid)?;
        // Virtual-hosted addressing: the bucket is part of the host, which is what
        // AWS requires for buckets created since 2020 and what every compatible
        // vendor accepts. Path style would sign a different canonical request, so
        // this is a signing decision rather than a cosmetic one.
        let host = format!("{bucket}.{host}");
        let (stamp, date) = timestamps(now);
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let canonical_path = format!("/{}", encode(key, true));
        let query = format!(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={stamp}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
            encode(&format!("{}/{scope}", self.access_key_id), false)
        );
        let canonical =
            format!("{method}\n{canonical_path}\n{query}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let signature = hex(&hmac(&self.signing_key(&date), &to_sign));
        Ok(format!(
            "https://{host}{canonical_path}?{query}&X-Amz-Signature={signature}"
        ))
    }
}

/// Turn an object-store HTTP response into the value an application sees.
///
/// Returns the result and whether the outcome is unknown. Absence is not an error
/// in either operation, and that is the substantive decision here: a HEAD asking
/// "is this there?" is answered by 404 just as truthfully as by 200, and an S3
/// DELETE is idempotent — deleting a key that was never there reports the same 204
/// as deleting one that was. Reporting either as a failure would push an
/// application into treating a correct answer as an error.
pub(super) fn response(
    profile: &super::ResponseProfile,
    response: &super::WireResponse,
) -> (Result<String, AdapterError>, bool) {
    let metadata = |name: &str| {
        response
            .metadata
            .iter()
            .find(|(header, _)| *header == name)
            .map(|(_, value)| value.as_str())
    };
    match (profile, response.status) {
        (super::ResponseProfile::ObjectHead, 200) => {
            let size = metadata("content-length")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or_default();
            let json = serde_json::json!({
                "exists": true,
                "size": size,
                "etag": metadata("etag").unwrap_or_default(),
                "last_modified": metadata("last-modified").unwrap_or_default(),
            });
            (Ok(json.to_string()), false)
        }
        (super::ResponseProfile::ObjectHead, 404) => (
            Ok(
                serde_json::json!({"exists":false,"size":0,"etag":"","last_modified":""})
                    .to_string(),
            ),
            false,
        ),
        (super::ResponseProfile::ObjectDelete, 200 | 204 | 404) => {
            (Ok(serde_json::json!({"deleted":true}).to_string()), false)
        }
        (_, 401 | 403) => (Err(AdapterError::ProviderDenied), false),
        (_, 429) => (Err(AdapterError::RateLimited), false),
        // Anything else leaves the store's state genuinely unknown to us.
        _ => (Err(AdapterError::Incomplete), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example published in AWS's Signature Version 4 documentation for
    /// a presigned GET.
    ///
    /// This is the base that establishes signing correctness, and it comes from
    /// AWS rather than from this code. A signer checked only against its own
    /// verifier agrees with itself about a wrong canonical request and fails
    /// against the real store; only a vendor-produced vector settles it.
    const ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    /// 2013-05-24T00:00:00Z, the example's signing instant.
    const SIGNED_AT: i64 = 1_369_353_600;
    const EXPECTED: &str = "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404";

    fn signer() -> Signer<'static> {
        Signer {
            access_key_id: ACCESS_KEY,
            secret: SECRET,
            region: "us-east-1",
        }
    }

    #[test]
    fn the_published_aws_presign_vector_matches() {
        let url = signer()
            .presign(
                "GET",
                "https://s3.amazonaws.com",
                "examplebucket",
                "test.txt",
                86_400,
                SIGNED_AT,
            )
            .expect("signable");
        assert!(
            url.contains(&format!("X-Amz-Signature={EXPECTED}")),
            "signature does not match AWS's published example: {url}"
        );
    }

    fn reply(status: u16, metadata: Vec<(&'static str, String)>) -> super::super::WireResponse {
        super::super::WireResponse {
            status,
            json_content_type: false,
            body: vec![],
            request_id: None,
            metadata,
        }
    }

    /// Absence is an answer, not a failure — for both operations, for different
    /// reasons, and neither reason is obvious enough to leave unwritten.
    #[test]
    fn a_missing_object_is_reported_rather_than_failed() {
        // A HEAD asking "is this there?" is answered by 404 as truthfully as by
        // 200. Returning an error would make an application catch a fault to learn
        // an ordinary fact.
        let (result, unknown) = response(
            &super::super::ResponseProfile::ObjectHead,
            &reply(404, vec![]),
        );
        assert!(!unknown);
        let value: serde_json::Value = serde_json::from_str(&result.expect("answered")).unwrap();
        assert_eq!(value["exists"], serde_json::json!(false));

        // A DELETE is idempotent in the stores this speaks to: removing a key that
        // was never there reports success, and a retry after a lost response must
        // therefore not look like a different outcome than the first attempt.
        for status in [200, 204, 404] {
            let (result, unknown) = response(
                &super::super::ResponseProfile::ObjectDelete,
                &reply(status, vec![]),
            );
            assert!(!unknown, "{status}");
            let value: serde_json::Value =
                serde_json::from_str(&result.expect("answered")).unwrap();
            assert_eq!(value["deleted"], serde_json::json!(true), "{status}");
        }
    }

    #[test]
    fn a_head_reports_what_the_store_said_and_a_refusal_stays_a_refusal() {
        let (result, unknown) = response(
            &super::super::ResponseProfile::ObjectHead,
            &reply(
                200,
                vec![
                    ("content-length", "4096".into()),
                    ("etag", "\"abc\"".into()),
                ],
            ),
        );
        assert!(!unknown);
        let value: serde_json::Value = serde_json::from_str(&result.expect("answered")).unwrap();
        assert_eq!(value["exists"], serde_json::json!(true));
        assert_eq!(value["size"], serde_json::json!(4096));

        // Denial and rate limiting are not absence and must not be reported as a
        // confident "no".
        for (status, expected) in [
            (403, AdapterError::ProviderDenied),
            (429, AdapterError::RateLimited),
        ] {
            let (result, _) = response(
                &super::super::ResponseProfile::ObjectHead,
                &reply(status, vec![]),
            );
            assert_eq!(result.unwrap_err(), expected, "{status}");
        }
        // Anything else leaves the store's state genuinely unknown, which the
        // caller must be told rather than shown a default.
        let (result, unknown) = response(
            &super::super::ResponseProfile::ObjectHead,
            &reply(500, vec![]),
        );
        assert!(result.is_err() && unknown);
    }

    #[test]
    fn the_signed_method_is_part_of_the_signature() {
        // A URL signed for HEAD cannot be reused as a DELETE. This is what makes
        // it safe for the same signing path to serve all four operations: the
        // operation is fixed at signing time, not chosen by whoever holds the URL.
        let head = signer()
            .presign(
                "HEAD",
                "https://s3.amazonaws.com",
                "examplebucket",
                "test.txt",
                900,
                SIGNED_AT,
            )
            .expect("signable");
        let delete = signer()
            .presign(
                "DELETE",
                "https://s3.amazonaws.com",
                "examplebucket",
                "test.txt",
                900,
                SIGNED_AT,
            )
            .expect("signable");
        let signature = |url: &str| {
            url.split("X-Amz-Signature=")
                .nth(1)
                .expect("signed")
                .to_owned()
        };
        assert_ne!(
            signature(&head),
            signature(&delete),
            "the same signature authorized two different methods"
        );
    }

    #[test]
    fn the_timestamp_rendering_is_the_one_the_signature_covers() {
        // The format is part of the string to sign, so a differing rendering is a
        // differing signature. Checked against the example's own stamp.
        assert_eq!(
            timestamps(SIGNED_AT),
            ("20130524T000000Z".to_owned(), "20130524".to_owned())
        );
        // A leap day, which a hand-rolled civil-from-days gets wrong.
        assert_eq!(timestamps(1_709_164_800).0, "20240229T000000Z");
    }
}
