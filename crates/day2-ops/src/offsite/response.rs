//! Closed provider response DATA. No provider/parser/IO error or foreign value
//! enters the returned error chain. Limits bound observed body bytes, not a
//! claim about every allocation or reqwest/header-internal secret copy.
use serde::{
    Deserialize, Deserializer,
    de::{DeserializeOwned, MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{error::Error, fmt, io::Read};
use zeroize::Zeroizing;

const MAX_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug)]
pub(super) enum Stage {
    Metadata,
    Object,
}

#[derive(Clone, Copy, Debug)]
enum Cause {
    Transport,
    Status,
    Read,
    Oversize,
    Codec,
    Mismatch,
}

#[derive(Debug)]
pub(super) struct Refused {
    stage: Stage,
    cause: Cause,
    status: Option<u16>,
    body_bytes: usize,
    secondary_read: Option<Cause>,
}

impl Refused {
    pub(super) fn transport(stage: Stage) -> Self {
        Self {
            stage,
            cause: Cause::Transport,
            status: None,
            body_bytes: 0,
            secondary_read: None,
        }
    }

    fn observed(stage: Stage, cause: Cause, status: u16, body_bytes: usize) -> Self {
        Self {
            stage,
            cause,
            status: Some(status),
            body_bytes,
            secondary_read: None,
        }
    }
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "offsite_{:?}_{:?} status={:?} body_bytes={} secondary_read={:?}",
            self.stage, self.cause, self.status, self.body_bytes, self.secondary_read
        )
    }
}

impl Error for Refused {}

// Derived structs also accept positional sequences in serde. Force the actual
// JSON object visitor without building an allocating serde_json::Value copy.
fn decode_map<T: DeserializeOwned>(body: &[u8]) -> Result<T, ()> {
    struct ObjectOnly<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectOnly<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a provider object")
        }
        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(MapAccessDeserializer::new(map))
        }
    }
    let mut decoder = serde_json::Deserializer::from_slice(body);
    let value = (&mut decoder)
        .deserialize_map(ObjectOnly::<T>(std::marker::PhantomData))
        .map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    Ok(value)
}

fn read_body(
    reader: &mut impl Read,
    stage: Stage,
    status: u16,
) -> Result<Zeroizing<Vec<u8>>, Refused> {
    let mut body = Zeroizing::new(vec![0_u8; MAX_BYTES + 1]);
    let mut consumed = 0;
    loop {
        match reader.read(&mut body[consumed..]) {
            Ok(0) => {
                body.truncate(consumed);
                return Ok(body);
            }
            Ok(read) => {
                consumed += read;
                if consumed > MAX_BYTES {
                    return Err(Refused::observed(stage, Cause::Oversize, status, consumed));
                }
            }
            Err(_) => return Err(Refused::observed(stage, Cause::Read, status, consumed)),
        }
    }
}

fn response(
    reader: &mut impl Read,
    stage: Stage,
    status: u16,
) -> Result<Zeroizing<Vec<u8>>, Refused> {
    // Read under the SAME existing request timeout, also on status rejection.
    // Count only bytes actually returned, never advertised Content-Length.
    let body = read_body(reader, stage, status);
    if !(200..300).contains(&status) {
        let (bytes, secondary_read) = match &body {
            Ok(body) => (body.len(), None),
            Err(error) => (error.body_bytes, Some(error.cause)),
        };
        return Err(Refused {
            stage,
            cause: Cause::Status,
            status: Some(status),
            body_bytes: bytes,
            secondary_read,
        });
    }
    body
}

// Zeroize an owned parsed string even if a later field/duplicate/unknown key
// causes deserialization to fail before its containing record is constructed.
pub(super) struct PrivateText(Zeroizing<String>);

impl<'de> Deserialize<'de> for PrivateText {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        String::deserialize(decoder).map(|text| Self(Zeroizing::new(text)))
    }
}

impl PrivateText {
    pub(super) fn for_header(&self) -> &str {
        &self.0
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    access_token: PrivateText,
    token_type: PrivateText,
    expires_in: u64,
}

pub(super) fn token(reader: &mut impl Read, status: u16) -> Result<PrivateText, Refused> {
    let body = response(reader, Stage::Metadata, status)?;
    let fail = || Refused::observed(Stage::Metadata, Cause::Codec, status, body.len());
    let token: Token = decode_map(&body).map_err(|_| fail())?;
    if !token.token_type.0.eq_ignore_ascii_case("bearer")
        || token.access_token.0.is_empty()
        || !token.access_token.0.bytes().all(|b| b.is_ascii_graphic())
        || token.expires_in == 0
    {
        return Err(fail());
    }
    // expires_in is validated DATA, never a Job/native grant or renewed clock.
    Ok(token.access_token)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Object {
    name: PrivateText,
    bucket: PrivateText,
    size: PrivateText,
    generation: PrivateText,
}

fn decimal(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let parsed: u64 = value.parse().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

pub(super) fn object(
    reader: &mut impl Read,
    status: u16,
    expected_name: &str,
    expected_bucket: &str,
    expected_bytes: u64,
) -> Result<u64, Refused> {
    let body = response(reader, Stage::Object, status)?;
    let fail = |cause| Refused::observed(Stage::Object, cause, status, body.len());
    let object: Object = decode_map(&body).map_err(|_| fail(Cause::Codec))?;
    let size = decimal(&object.size.0).ok_or_else(|| fail(Cause::Codec))?;
    let generation = decimal(&object.generation.0)
        .filter(|v| *v > 0 && *v <= i64::MAX as u64)
        .ok_or_else(|| fail(Cause::Codec))?;
    if object.name.0.as_str() != expected_name
        || object.bucket.0.as_str() != expected_bucket
        || size != expected_bytes
    {
        return Err(fail(Cause::Mismatch));
    }
    Ok(generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    const TOKEN: &[u8] = br#"{"access_token":"test-token","token_type":"Bearer","expires_in":300}"#;
    const OBJECT: &[u8] = br#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":"19"}"#;
    const PRIVATE: &str = "not-a-secret";

    fn refused<T>(result: Result<T, Refused>) -> Refused {
        match result {
            Err(error) => error,
            Ok(_) => panic!("closed provider response admitted"),
        }
    }

    fn private_error(error: Refused) {
        let error = anyhow::Error::new(error);
        assert_eq!(error.chain().count(), 1);
        for shown in [
            error.to_string(),
            format!("{error:#}"),
            format!("{error:?}"),
        ] {
            assert!(!shown.contains(PRIVATE));
            assert!(!shown.contains("access_token"));
        }
    }

    #[test]
    fn required_metadata_contract_refuses_duplicates_shapes_and_private_foreign_fields() {
        assert_eq!(
            token(&mut &TOKEN[..], 200)
                .unwrap_or_else(|_| panic!("valid token refused"))
                .for_header(),
            "test-token"
        );
        for input in [
            r#"{"access_token":"not-a-secret","token_type":"wrong","expires_in":300}"#,
            r#"{"access_token":"test-token","access_\u0074oken":"not-a-secret","token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":300,"expires_in":300}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":300,"not-a-secret":"value"}"#,
            r#"{"access_token":null,"token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":7,"token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":"","token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":"bad\nvalue","token_type":"Bearer","expires_in":300}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":0}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":-1}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":"300"}"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":18446744073709551616}"#,
            r#"{"access_token":"test-token","token_type":"Bearer"}"#,
            r#"{"access_token":"test-token","expires_in":300}"#,
            r#"{"token_type":"Bearer","expires_in":300}"#,
            r#"[{"access_token":"test-token","token_type":"Bearer","expires_in":300}]"#,
            r#"["test-token","Bearer",300]"#,
            r#"{"access_token":"test-token","token_type":"Bearer","expires_in":300} {}"#,
        ] {
            private_error(refused(token(&mut input.as_bytes(), 200)));
        }
    }

    #[test]
    fn projected_object_contract_requires_exact_selection_and_bounded_numeric_strings() {
        let parse = |bytes: &[u8]| {
            object(
                &mut &bytes[..],
                200,
                "app/slot/app.sqlite",
                "example-backups",
                7,
            )
        };
        assert_eq!(parse(OBJECT).unwrap(), 19);
        for input in [
            r#"{"name":"not-a-secret","bucket":"example-backups","size":"7","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"not-a-secret","size":"7","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"not-a-secret","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":"not-a-secret"}"#,
            r#"{"name":"app/slot/app.sqlite","na\u006de":"not-a-secret","bucket":"example-backups","size":"7","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":"19","not-a-secret":{}}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":7,"generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"8","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"07","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"18446744073709551616","generation":"19"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":"0"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":"9223372036854775808"}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7","generation":19}"#,
            r#"{"name":"app/slot/app.sqlite","bucket":"example-backups","size":"7"}"#,
            r#"["app/slot/app.sqlite","example-backups","7","19"]"#,
            "null",
            "[]",
        ] {
            private_error(refused(parse(input.as_bytes())));
        }
        assert_eq!(object(&mut &br#"{"name":"n","bucket":"b","size":"18446744073709551615","generation":"9223372036854775807"}"#[..], 200,"n","b",u64::MAX).unwrap(),i64::MAX as u64);
    }

    #[derive(Debug)]
    struct Foreign;
    impl fmt::Display for Foreign {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            panic!("foreign Display invoked")
        }
    }
    impl Error for Foreign {}

    struct Partial {
        data: &'static [u8],
        returned: usize,
        calls: usize,
    }
    impl Read for Partial {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.calls += 1;
            if self.returned != 0 {
                return Err(std::io::Error::other(Foreign));
            }
            let count = self.data.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.data[..count]);
            self.returned = count;
            Ok(count)
        }
    }

    #[test]
    fn observed_byte_bound_and_partial_reads_keep_status_primary_without_foreign_errors() {
        let mut exact = TOKEN.to_vec();
        exact.resize(MAX_BYTES, b' ');
        assert!(token(&mut &exact[..], 200).is_ok());
        exact.push(b' ');
        let error = refused(token(&mut &exact[..], 200));
        assert!(matches!(error.cause, Cause::Oversize));
        assert_eq!(error.body_bytes, MAX_BYTES + 1);
        private_error(error);
        for status in [200, 403] {
            let mut reader = Partial {
                data: b"not-a-secret",
                returned: 0,
                calls: 0,
            };
            let error = refused(token(&mut reader, status));
            assert_eq!(error.body_bytes, reader.data.len());
            assert_eq!(reader.calls, 2);
            if status == 200 {
                assert!(matches!(error.cause, Cause::Read));
            } else {
                assert!(matches!(error.cause, Cause::Status));
                assert!(matches!(error.secondary_read, Some(Cause::Read)));
            }
            private_error(error);
        }
        for status in [199, 300, 400, 412, 500] {
            let error = refused(object(&mut &PRIVATE.as_bytes()[..], status, "n", "b", 0));
            assert!(matches!(error.cause, Cause::Status));
            assert_eq!(error.status, Some(status));
            assert_eq!(error.body_bytes, PRIVATE.len());
            private_error(error);
        }
    }
}
