//! Signing keys below are synthetic test-only RSA keys generated for this suite.
//! They sign nothing outside these tests and are allowlisted for secret scanning
//! by exact path.
use super::*;
use ring::rand::SystemRandom;

const TEST_ID: &str = "aenkglomgaiikbngepnbfminfpfgmape";
const OTHER_ID: &str = "mannldagfnengdmfogklaghjlifalmep";
// Signed by Chrome's own --pack-extension (GoLinks 1.0.0), not by this module.
const CHROME_PACKED_ID: &str = "jldmikbinomhomcbmeppagennfohakni";

const TEST_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCf79UH0lu3vAP1\n\
y4dyw9y0Ccew9FhG5yPKGnALEjP6/GcHffF2vXR3+4FBWLtUupfCfQVASEkTPqQe\n\
Jatxisp5odHx46ptk9ZjmIm3p04J+Se+9TxcjdXlcYeWteKJZQ+T8uyqN0xMH2gy\n\
jxPb5s6961olG5mZZv5z9sYjWwMmrj3ov7QAXWPgbPjdJl8+xh4rCw6Ku7Q4UTHO\n\
VmXIMNOSAjqLx6cC9+lgFuEMA1lYVnGN+DnwC3OpJbNhzPQrcpdJEqnZv5GrJH4G\n\
Gjt3yToAA9ya6rBrcFRtHy8PqlXqp04eTygTIb+0qluLFZ2RGgDbGMzIc+IaxyVG\n\
RiqAijdhAgMBAAECggEAM3zYDd6QnEOw2q4c+rtHD8aePL9Ms/axNNzx+P5xMXmU\n\
CXtoApvXJNEYuVrBY/N166ynxhv/OmzOFM53tOPDbwjDN6XdNc2EFSgEHdWEb/1/\n\
6B+2wO0AUQ8NYV1IgobATxbDTcDjlRX/S1d4QzC4mbdsm8mY1yOrAtYMz1D7YLXw\n\
q/SUgvJ/sWzobl2MXrHGqxZ2O+oeAf0hqOvjhUbIw5B8hE9jJWfM3/U6pSS03q2q\n\
gK73kU7q8COP3GCzl2iweR7JW2kR8ptJk4ar75QdEC7sNF6T3QEjUTyAlmIhm7me\n\
BY8GKP1wRiCykOXWTeszBjpWCr12QacJxl7XT5eFqQKBgQDY2vZZ6VHslB1AIkTd\n\
9KMPwJOgyVvrVljNxmRPytiXbMDRTj/BI0d48P4BgALegsILCTyDZPNZe/gFr9ZG\n\
RlMOHdHr/J49uXlZrH4rrgyDcEKqkHqlW5rfKL+Igy+LGHs3CWdkJd8r/KxyDGbM\n\
8V6qVJdXBcihlQUry7vacndZpwKBgQC8zqB0hfXPuwNs+Zz20KzhXVLwNsbsYpNF\n\
gGp/M0OIuuxss3Ljgpxwb9kjkJJzLFSJrZtDm6/3b8NQKw13juu//fQ+evAYteHW\n\
1EFtpwijlKH1TqtA6r2ZWT79BzFVgz0hENDPvrgv72hRSvBxyepCogI+1F26mYth\n\
D3a1UZ/3twKBgQDPdvRW4pRhHPa7A84U9tYF3Pyfx+Sryqkc/N+9QthiTkZOOGlg\n\
MotPVmf8MWcNT9Wqz0RYhH0YMDUB487A3sjY6YiLF9ygOtCxDQiMa3BHU2BEZAMi\n\
LfiF5SsQxEj47wv6hIGo216ea5bjaZ/0FDu4A0PimoLuq24OD1UCUZ6DYwKBgQCG\n\
rLCBTUiQOypvYgFXgHPAcQwG8lukI5A/BCFyyANFFWgtBTdPF0w1W2K8XpRH+Pf4\n\
GNBmQjgbPCpKFduOS3DXyvKcWp7GUX5c+ZwN9hZQcGWyD8JSFN7W8nTekXHcODez\n\
TUZU2QqSjqePTPADim5Bx0Powxx0TK/BtQEMxsNfMwKBgQCDRqIhH5I2/HMBYTLs\n\
C8+KSlnlZcQsvTBhdg7S/71VqM8MqDkIjpyzTPZsvzXpbe2oO2YzcXascgoLaLO+\n\
WrubG+3xKYa3fHvtvx8MIYpxBaFqmMhOpztNbW8KpqvWa98gPIGTAdnWIiIVcgc0\n\
tY7u5tV4dYlmYebe7hOuockSrQ==\n\
-----END PRIVATE KEY-----\n\
";
const TEST_KEY_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpQIBAAKCAQEAn+/VB9Jbt7wD9cuHcsPctAnHsPRYRucjyhpwCxIz+vxnB33x\n\
dr10d/uBQVi7VLqXwn0FQEhJEz6kHiWrcYrKeaHR8eOqbZPWY5iJt6dOCfknvvU8\n\
XI3V5XGHlrXiiWUPk/LsqjdMTB9oMo8T2+bOvetaJRuZmWb+c/bGI1sDJq496L+0\n\
AF1j4Gz43SZfPsYeKwsOiru0OFExzlZlyDDTkgI6i8enAvfpYBbhDANZWFZxjfg5\n\
8AtzqSWzYcz0K3KXSRKp2b+RqyR+Bho7d8k6AAPcmuqwa3BUbR8vD6pV6qdOHk8o\n\
EyG/tKpbixWdkRoA2xjMyHPiGsclRkYqgIo3YQIDAQABAoIBADN82A3ekJxDsNqu\n\
HPq7Rw/Gnjy/TLP2sTTc8fj+cTF5lAl7aAKb1yTRGLlawWPzdeusp8Yb/zpszhTO\n\
d7Tjw28Iwzel3TXNhBUoBB3VhG/9f+gftsDtAFEPDWFdSIKGwE8Ww03A45UV/0tX\n\
eEMwuJm3bJvJmNcjqwLWDM9Q+2C18Kv0lILyf7Fs6G5djF6xxqsWdjvqHgH9Iajr\n\
44VGyMOQfIRPYyVnzN/1OqUktN6tqoCu95FO6vAjj9xgs5dosHkeyVtpEfKbSZOG\n\
q++UHRAu7DRek90BI1E8gJZiIZu5ngWPBij9cEYgspDl1k3rMwY6Vgq9dkGnCcZe\n\
10+XhakCgYEA2Nr2WelR7JQdQCJE3fSjD8CToMlb61ZYzcZkT8rYl2zA0U4/wSNH\n\
ePD+AYAC3oLCCwk8g2TzWXv4Ba/WRkZTDh3R6/yePbl5Wax+K64Mg3BCqpB6pVua\n\
3yi/iIMvixh7NwlnZCXfK/yscgxmzPFeqlSXVwXIoZUFK8u72nJ3WacCgYEAvM6g\n\
dIX1z7sDbPmc9tCs4V1S8DbG7GKTRYBqfzNDiLrsbLNy44KccG/ZI5CScyxUia2b\n\
Q5uv92/DUCsNd47rv/30PnrwGLXh1tRBbacIo5Sh9U6rQOq9mVk+/QcxVYM9IRDQ\n\
z764L+9oUUrwccnqQqICPtRdupmLYQ92tVGf97cCgYEAz3b0VuKUYRz2uwPOFPbW\n\
Bdz8n8fkq8qpHPzfvULYYk5GTjhpYDKLT1Zn/DFnDU/Vqs9EWIR9GDA1AePOwN7I\n\
2OmIixfcoDrQsQ0IjGtwR1NgRGQDIi34heUrEMRI+O8L+oSBqNtenmuW42mf9BQ7\n\
uAND4pqC7qtuDg9VAlGeg2MCgYEAhqywgU1IkDsqb2IBV4BzwHEMBvJbpCOQPwQh\n\
csgDRRVoLQU3TxdMNVtivF6UR/j3+BjQZkI4GzwqShXbjktw18rynFqexlF+XPmc\n\
DfYWUHBlsg/CUhTe1vJ03pFx3Dg3s01GVNkKko6nj0zwA4puQcdD6MMcdEyvwbUB\n\
DMbDXzMCgYEAg0aiIR+SNvxzAWEy7AvPikpZ5WXELL0wYXYO0v+9VajPDKg5CI6c\n\
s0z2bL816W3tqDtmM3F2rHIKC2izvlq7mxvt8SmGt3x77b8fDCGKcQWhapjITqc7\n\
TW1vCqar1mvfIDyBkwHZ1iIiFXIHNLWO7ubVeHWJZmHm3u4TrqHJEq0=\n\
-----END RSA PRIVATE KEY-----\n\
";
const OTHER_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdUsgETzChyQ1l\n\
K+3zXRIb10L4QPuV7eNTGiKL86Akfj5nPyoX/Un7S17l0XXyUdTbZtQipIqJ1uSy\n\
Y96SVLwJ3amDncaH8GfGd8E0IW2tflnOw/YzYP1dPYcJFflauKQu5S8+q09vcrty\n\
Fwkp8Oc4nLE9Ls4e6J/UzXDYr1MafvwwJk+H5P1CAa0a1bI9pYN8aqzFT8BEZ4NH\n\
4ryDaWVJNuET6GJkeGi65znzMKcUMYmxeDr/a/aTXmlMbNqxLhnicVRP58WAAb8z\n\
yEPKv6o1plx8a+8/LKfCMdvPZJm3i2jK5x1NxA2mADHrV6zfSz6Mdudn6cVSETYL\n\
B6TqQlNhAgMBAAECggEAAf5uyu2WzmYchYy7lLSeqlWqSdH6nkxuiVR9qmWcp2Am\n\
OeuPnmnQymuKuPTuC40rJ0Czxy1r4au+KEVvW7SeBK396QCF59EnL4yMmU5XJ0/z\n\
owg4Xy+HTOtrtU5e/URbzr0lQfETFHS3mKf44lwx25wFlW+GoAoPHh5TpAHM1tTo\n\
e5rqUoB2NW9+oppqEVwl9cgvxfBX/GpqyLR8OQRD1lxMaB2oGhbhOV5sOpOaFY2V\n\
BMjOO4mfT9QonjdXxn/N5a9X1F9Rri2UlCjKma8r28vL41CyrCPqv52sp6WmltGf\n\
FSWmmbi2LC5HWHbOtE2fBxsfL+2MZ+ygcdBp9GDDcQKBgQDSZ1uL4mCm3p57yt21\n\
Hi7dkiSLZR/LzBHyRBddSs8xXv9UnDVEjVUCDIvkd8x4aBc9AeJ4tEHzWOHklyw8\n\
iWSDxHkqFOcIw6rElDAVsC2+5VM9GGoHROctvi3Utonhc9XMGbo+LkpPW1qv6v9y\n\
gqQjnddODMp8ClDburUWbujHBQKBgQC/aqo9Uqy9m+GpHVhgEQjDxX1v7kxVYlO3\n\
oHevI72B0qC4af7ejO0+iXr1Ax4zH9ioyiUx8fNxrO8oj4oZDpUBt4H2Kz0BzoFm\n\
8oMsK2g0fjst9ybVaVqXr66hqIJ/p9AmCmRdnwpTrwu7t1Apn28nxrHgyK4hrv3x\n\
YtvX5nKRrQKBgAFtvDxl7BwV9OOITBsXul+8x0y/AglDOHf5qGL0yBVgvMEZUm9F\n\
umcKKMUDXzsOEeJTKfOB3dTGLLp9oEpE8I7Ifb4gaDUyBu3Qx8bN7HGYYwlOKiIk\n\
gKFZ4jvIhYUnYTNClXYooE6Lo0EAin1/j5fCUZzxD0rqUwQ671HYrPH1AoGADoia\n\
xG0ykHL1f1GrFCA2+iZUj9sYEKOWl6qna7Ta/rBvY5EouN0aZlUp8NB7yoXwfWBb\n\
0p78TPVEc1/yrFRfG/JC+93sk+aKDLb9Hq1tDA9JjwPk/u8w4bOFHuEch3TGaR0A\n\
4drhfdkcmvQgMgjY97wuZVLXZddTkLBg4NOuf0ECgYEAtLOZ402vqsAFZp9qX5O/\n\
1Vpd9XC8VV7Lq/3/NFyxPMI7LcmAFjDbFxK+yxDU5IkOBKhecxF2Q3rJlPxoWKbL\n\
Jzqi1MGpbGrX02MOpmIfYGNA3gAeVi36D4Qu++4Y1eveTy8Y7XHen94RVdVfQv2Y\n\
O1TXjweY/oryKKF6OPOI0f0=\n\
-----END PRIVATE KEY-----\n\
";
const TEST_PUBLIC_KEY: &str = "\
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn+/VB9Jbt7wD9cuHcsPctAnHsPRYRucj
    yhpwCxIz+vxnB33xdr10d/uBQVi7VLqXwn0FQEhJEz6kHiWrcYrKeaHR8eOqbZPWY5iJt6dOCfkn
    vvU8XI3V5XGHlrXiiWUPk/LsqjdMTB9oMo8T2+bOvetaJRuZmWb+c/bGI1sDJq496L+0AF1j4Gz4
    3SZfPsYeKwsOiru0OFExzlZlyDDTkgI6i8enAvfpYBbhDANZWFZxjfg58AtzqSWzYcz0K3KXSRKp
    2b+RqyR+Bho7d8k6AAPcmuqwa3BUbR8vD6pV6qdOHk8oEyG/tKpbixWdkRoA2xjMyHPiGsclRkYq
    gIo3YQIDAQAB
";
const OTHER_PUBLIC_KEY: &str = "\
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnVLIBE8wockNZSvt810SG9dC+ED7le3j
    Uxoii/OgJH4+Zz8qF/1J+0te5dF18lHU22bUIqSKidbksmPeklS8Cd2pg53Gh/BnxnfBNCFtrX5Z
    zsP2M2D9XT2HCRX5WrikLuUvPqtPb3K7chcJKfDnOJyxPS7OHuif1M1w2K9TGn78MCZPh+T9QgGt
    GtWyPaWDfGqsxU/ARGeDR+K8g2llSTbhE+hiZHhouuc58zCnFDGJsXg6/2v2k15pTGzasS4Z4nFU
    T+fFgAG/M8hDyr+qNaZcfGvvPyynwjHbz2SZt4toyucdTcQNpgAx61es30s+jHbnZ+nFUhE2Cwek
    6kJTYQIDAQAB
";
const CHROME_PACKED_CRX: &str = "\
    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
    AK8AAAClBwAAAAA=
";

fn unwrap_base64(lines: &str) -> Vec<u8> {
    STANDARD
        .decode(lines.split_whitespace().collect::<String>())
        .expect("fixture base64")
}

const UPDATE_URL: &str = "https://reminders.example.com/downloads/updates.xml";

fn binding() -> Binding {
    Binding {
        id: TEST_ID.into(),
        crx: "reminders.crx".into(),
        update_url: UPDATE_URL.into(),
    }
}

fn manifest_with(version: &str, extra: Value) -> Vec<u8> {
    let mut manifest = json!({
        "manifest_version": 3,
        "name": "Reminders",
        "version": version,
        "background": { "service_worker": "src/background.js", "type": "module" },
    });
    for (name, value) in extra.as_object().expect("extra object") {
        if value.is_null() {
            manifest.as_object_mut().expect("manifest").remove(name);
        } else {
            manifest[name] = value.clone();
        }
    }
    serde_json::to_vec_pretty(&manifest).expect("manifest")
}

fn source(version: &str) -> Files {
    Files::from([
        ("manifest.json".into(), manifest_with(version, json!({}))),
        (
            "src/background.js".into(),
            b"export const ready = true;\n".to_vec(),
        ),
        ("_locales/en/messages.json".into(), b"{}\n".to_vec()),
        (
            "icons/icon16.png".into(),
            vec![0x89, b'P', b'N', b'G', 0, 1, 2, 3],
        ),
    ])
}

fn pack_with(key: &str, source: &Files, downloads: &Files) -> Result<Package> {
    pack(
        &binding(),
        source,
        downloads,
        key.as_bytes(),
        &SystemRandom::new(),
    )
}

fn downloads(package: &Package) -> Files {
    Files::from([
        ("reminders.crx".into(), package.crx.clone()),
        (UPDATE_MANIFEST.into(), package.update_manifest.clone()),
    ])
}

fn error<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn extension_ids_match_an_independent_openssl_derivation() {
    assert_eq!(extension_id(&unwrap_base64(TEST_PUBLIC_KEY)), TEST_ID);
    assert_eq!(extension_id(&unwrap_base64(OTHER_PUBLIC_KEY)), OTHER_ID);
}

#[test]
fn a_package_signed_by_chrome_itself_verifies() -> Result<()> {
    let crx = unwrap_base64(CHROME_PACKED_CRX);
    let (public_key, archive) = open(&crx)?;
    assert_eq!(extension_id(public_key), CHROME_PACKED_ID);
    assert!(archive.starts_with(b"PK\x03\x04"));
    let mut tampered = crx.clone();
    let last = tampered.len() - 30;
    tampered[last] ^= 1;
    assert!(error(open(&tampered)).contains("invalid signature"));
    Ok(())
}

#[test]
fn crc32_matches_the_standard_check_value() {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn packing_is_deterministic_and_verifies_against_source() -> Result<()> {
    let source = source("1.2.0");
    let package = pack_with(TEST_KEY, &source, &Files::new())?;
    let again = pack_with(TEST_KEY_PKCS1, &source, &Files::new())?;
    assert_eq!(
        package.crx, again.crx,
        "PKCS#8 and PKCS#1 encodings sign identically"
    );
    let release = verify(&binding(), &source, &downloads(&package))?;
    assert_eq!(release, package.release);
    assert_eq!(release.extension_id, TEST_ID);
    assert_eq!(release.version, "1.2.0");
    assert_eq!(
        release.codebase,
        "https://reminders.example.com/downloads/reminders.crx"
    );
    assert_eq!(release.crx_digest, crate::digest(&package.crx));
    assert_eq!(
        String::from_utf8(package.update_manifest)?,
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<gupdate xmlns=\"http://www.google.com/update2/response\" protocol=\"2.0\">\n",
            "  <app appid=\"aenkglomgaiikbngepnbfminfpfgmape\">\n",
            "    <updatecheck codebase=\"https://reminders.example.com/downloads/reminders.crx\" version=\"1.2.0\" />\n",
            "  </app>\n",
            "</gupdate>\n",
        )
    );
    let (public_key, archive) = open(&package.crx)?;
    assert_eq!(extension_id(public_key), TEST_ID);
    let released = released(&binding(), &source, &manifest(&source)?, public_key)?;
    assert_eq!(archive, zip(&released)?);
    assert_eq!(
        released.keys().collect::<Vec<_>>(),
        source.keys().collect::<Vec<_>>()
    );
    let packed: Value = serde_json::from_slice(&released["manifest.json"])?;
    assert_eq!(
        packed["key"],
        TEST_PUBLIC_KEY.split_whitespace().collect::<String>(),
        "the release names its signing key's public key"
    );
    assert_eq!(packed["update_url"], UPDATE_URL);
    assert_eq!(packed["name"], "Reminders");
    Ok(())
}

#[test]
fn the_archive_is_a_plain_stored_zip_in_path_order() -> Result<()> {
    let archive = zip(&source("1"))?;
    let names = archive
        .windows(4)
        .enumerate()
        .filter(|(_, window)| *window == b"PK\x03\x04")
        .map(|(offset, _)| {
            let length = u16::from_le_bytes([archive[offset + 26], archive[offset + 27]]) as usize;
            assert_eq!(&archive[offset + 8..offset + 10], &[0, 0], "stored entry");
            String::from_utf8(archive[offset + 30..offset + 30 + length].to_vec()).expect("name")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "_locales/en/messages.json",
            "icons/icon16.png",
            "manifest.json",
            "src/background.js"
        ]
    );
    let end = archive.len() - 22;
    assert_eq!(&archive[end..end + 4], b"PK\x05\x06");
    assert_eq!(
        &archive[end + 8..end + 12],
        &[4, 0, 4, 0],
        "four entries, no comment"
    );
    assert_eq!(&archive[end + 20..], &[0, 0]);
    Ok(())
}

#[test]
fn minimum_chrome_version_is_published() -> Result<()> {
    let mut source = source("2");
    source.insert(
        "manifest.json".into(),
        manifest_with("2", json!({ "minimum_chrome_version": "120" })),
    );
    let package = pack_with(TEST_KEY, &source, &Files::new())?;
    assert!(
        String::from_utf8(package.update_manifest)?
            .contains(" version=\"2\" prodversionmin=\"120\" />")
    );
    Ok(())
}

#[test]
fn only_the_pinned_signing_key_can_release() -> Result<()> {
    let message = error(pack_with(OTHER_KEY, &source("1"), &Files::new()));
    assert!(
        message.contains("chrome_extension_signing_key") && message.contains("day2.json pins"),
        "{message}"
    );
    let other = Binding {
        id: OTHER_ID.into(),
        ..binding()
    };
    let foreign = pack(
        &other,
        &source("1"),
        &Files::new(),
        OTHER_KEY.as_bytes(),
        &SystemRandom::new(),
    )?;
    assert!(
        error(verify(&binding(), &source("1"), &downloads(&foreign)))
            .contains("chrome_extension_identity"),
        "another extension's release never verifies against this pin"
    );
    assert!(
        error(pack(
            &binding(),
            &source("1"),
            &Files::new(),
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
            &SystemRandom::new(),
        ))
        .contains("unencrypted RSA private key")
    );
    Ok(())
}

#[test]
fn verification_rejects_stale_tampered_and_incomplete_releases() -> Result<()> {
    let original = source("1.0");
    let package = pack_with(TEST_KEY, &original, &Files::new())?;
    let mut edited = original.clone();
    edited.insert(
        "src/background.js".into(),
        b"export const ready = false;\n".to_vec(),
    );
    assert!(
        error(verify(&binding(), &edited, &downloads(&package))).contains("chrome_extension_stale")
    );

    let mut tampered = downloads(&package);
    let crx = tampered.get_mut("reminders.crx").expect("crx");
    let index = crx.len() - 40;
    crx[index] ^= 0x20;
    assert!(error(verify(&binding(), &original, &tampered)).contains("invalid signature"));

    let mut wrong_xml = downloads(&package);
    wrong_xml.insert(
        UPDATE_MANIFEST.into(),
        String::from_utf8(package.update_manifest.clone())?
            .replace("version=\"1.0\"", "version=\"1.1\"")
            .into_bytes(),
    );
    assert!(
        error(verify(&binding(), &original, &wrong_xml))
            .contains("chrome_extension_update_manifest")
    );

    let mut extra = downloads(&package);
    extra.insert("other.crx".into(), package.crx.clone());
    assert!(error(verify(&binding(), &original, &extra)).contains("chrome_extension_downloads"));
    let mut missing = downloads(&package);
    missing.remove(UPDATE_MANIFEST);
    assert!(error(verify(&binding(), &original, &missing)).contains("chrome_extension_downloads"));
    Ok(())
}

#[test]
fn apps_without_a_pin_publish_no_downloads() {
    assert!(verify_unpinned(&Files::new()).is_ok());
    for name in ["tool.crx", UPDATE_MANIFEST, "notes.xml"] {
        assert!(
            error(verify_unpinned(&Files::from([(name.into(), vec![1])])))
                .contains("chrome_extension_unpinned"),
            "{name}"
        );
    }
}

#[test]
fn releases_must_bump_the_version_when_the_extension_changes() -> Result<()> {
    let first = pack_with(TEST_KEY, &source("1.4"), &Files::new())?;
    let previous = downloads(&first);
    let repeated = pack_with(TEST_KEY, &source("1.4.0"), &previous);
    assert!(
        error(repeated).contains("chrome_extension_version"),
        "1.4.0 equals 1.4 but its manifest bytes differ"
    );
    assert_eq!(
        pack_with(TEST_KEY, &source("1.4"), &previous)?.crx,
        first.crx
    );

    let mut changed = source("1.4");
    changed.insert(
        "src/background.js".into(),
        b"export const ready = 2;\n".to_vec(),
    );
    assert!(error(pack_with(TEST_KEY, &changed, &previous)).contains("chrome_extension_version"));
    assert!(
        error(pack_with(TEST_KEY, &source("1.3.9"), &previous))
            .contains("chrome_extension_downgrade")
    );
    let mut bumped = changed.clone();
    bumped.insert("manifest.json".into(), manifest_with("1.10", json!({})));
    assert_eq!(
        pack_with(TEST_KEY, &bumped, &previous)?.release.version,
        "1.10"
    );

    let mut half = previous.clone();
    half.remove(UPDATE_MANIFEST);
    assert!(error(pack_with(TEST_KEY, &source("1.5"), &half)).contains("half of a release"));
    Ok(())
}

#[test]
fn manifests_are_validated_before_signing() {
    let cases = [
        (
            json!({ "manifest_version": 2 }),
            "manifest_version must be 3",
        ),
        (json!({ "version": "01" }), "invalid Chrome version"),
        (json!({ "version": "1.2.3.4.5" }), "invalid Chrome version"),
        (json!({ "version": "0.0" }), "invalid Chrome version"),
        (json!({ "version": "65536" }), "invalid Chrome version"),
        (json!({ "name": null }), "`name` must be a string"),
        (
            json!({ "key": TEST_PUBLIC_KEY.split_whitespace().collect::<String>() }),
            "remove `key`",
        ),
        (json!({ "update_url": UPDATE_URL }), "remove `update_url`"),
        (
            json!({ "minimum_chrome_version": 120 }),
            "minimum_chrome_version must be a string",
        ),
    ];
    for (extra, expected) in cases {
        let mut files = source("1");
        files.insert("manifest.json".into(), manifest_with("1", extra.clone()));
        let message = error(pack_with(TEST_KEY, &files, &Files::new()));
        assert!(message.contains(expected), "{extra}: {message}");
    }
    let mut missing = source("1");
    missing.remove("manifest.json");
    assert!(error(policy(&binding(), &missing)).contains("manifest.json is missing"));
}

#[test]
fn extension_paths_are_portable_and_unreserved() {
    for path in [
        ".DS_Store",
        "src/.hidden.js",
        "_metadata/verified_contents.json",
        "src/../x.js",
        "src//x.js",
        "src/x y.js",
    ] {
        let mut files = source("1");
        files.insert(path.into(), vec![1]);
        assert!(
            error(policy(&binding(), &files)).contains("chrome_extension_path"),
            "{path}"
        );
    }
    let mut conflict = source("1");
    conflict.insert("src".into(), vec![1]);
    assert!(error(policy(&binding(), &conflict)).contains("share a name"));
}

#[test]
fn pins_name_an_id_a_crx_download_and_an_update_manifest_url() {
    assert!(binding().validate().is_ok());
    for (id, crx, update_url) in [
        (
            "AENKGLOMGAIIKBNGEPNBFMINFPFGMAPE",
            "reminders.crx",
            UPDATE_URL,
        ),
        (
            "aenkglomgaiikbngepnbfminfpfgmapq",
            "reminders.crx",
            UPDATE_URL,
        ),
        (TEST_ID, "reminders.zip", UPDATE_URL),
        (TEST_ID, "../reminders.crx", UPDATE_URL),
        (
            TEST_ID,
            "reminders.crx",
            "http://reminders.example.com/downloads/updates.xml",
        ),
        (
            TEST_ID,
            "reminders.crx",
            "https://reminders.example.com/updates.xml",
        ),
        (
            TEST_ID,
            "reminders.crx",
            "https://reminders.example.com:8443/downloads/updates.xml",
        ),
        (
            TEST_ID,
            "reminders.crx",
            "https://user@reminders.example.com/downloads/updates.xml",
        ),
    ] {
        let pin = Binding {
            id: id.into(),
            crx: crx.into(),
            update_url: update_url.into(),
        };
        assert!(pin.validate().is_err(), "{pin:?}");
        assert!(policy(&pin, &source("1")).is_err(), "{pin:?}");
    }
}

#[test]
fn local_builds_keep_the_release_identity_only_without_an_overlay() -> Result<()> {
    let released = downloads(&pack_with(TEST_KEY, &source("1"), &Files::new())?);
    // A local build tests sources the release does not hold yet.
    let source = source("2");
    let plain = local(&binding(), &source, &released, &Files::new())?;
    let manifest: Value = serde_json::from_slice(&plain["manifest.json"])?;
    assert!(manifest.get("update_url").is_none());
    assert_eq!(manifest["name"], "Reminders");
    assert_eq!(
        manifest["key"],
        TEST_PUBLIC_KEY.split_whitespace().collect::<String>()
    );
    assert_eq!(plain["src/background.js"], source["src/background.js"]);
    assert!(
        error(local(&binding(), &source, &Files::new(), &Files::new())).contains("pack one first")
    );

    let overlay = Files::from([("src/background.js".into(), b"// observe only\n".to_vec())]);
    let changed = local(&binding(), &source, &Files::new(), &overlay)?;
    let manifest: Value = serde_json::from_slice(&changed["manifest.json"])?;
    assert!(manifest.get("key").is_none() && manifest.get("update_url").is_none());
    assert_eq!(manifest["name"], "Reminders (local)");
    assert_eq!(changed["src/background.js"], b"// observe only\n");

    let mut blocking = source.clone();
    blocking.insert(
        "manifest.json".into(),
        manifest_with(
            "1",
            json!({ "permissions": ["webRequest", "webRequestBlocking"] }),
        ),
    );
    let manifest: Value = serde_json::from_slice(
        &local(&binding(), &blocking, &Files::new(), &overlay)?["manifest.json"],
    )?;
    assert_eq!(
        manifest["permissions"],
        json!(["webRequest"]),
        "policy-only permission"
    );

    let replaced = Files::from([("manifest.json".into(), b"{}".to_vec())]);
    assert!(
        error(local(&binding(), &source, &released, &replaced))
            .contains("cannot replace manifest.json")
    );

    let other = Binding {
        id: OTHER_ID.into(),
        ..binding()
    };
    assert!(
        error(local(&other, &source, &released, &Files::new()))
            .contains("chrome_extension_identity"),
        "a build never takes another extension's key"
    );
    Ok(())
}

#[test]
fn policy_force_installs_from_the_published_update_manifest() -> Result<()> {
    assert_eq!(
        policy(&binding(), &source("3.1"))?,
        json!({
            "extension_id": TEST_ID,
            "version": "3.1",
            "update_url": "https://reminders.example.com/downloads/updates.xml",
            "admin_console": {
                "add": "Add Chrome app or extension by ID, From a custom URL",
                "installation_policy": "Force install",
                "installation_url": "https://reminders.example.com/downloads/updates.xml",
                "update_url": "Installation URL (see above)"
            },
            "chrome_policy": {
                "ExtensionSettings": {
                    TEST_ID: {
                        "installation_mode": "force_installed",
                        "update_url": "https://reminders.example.com/downloads/updates.xml",
                        "override_update_url": true
                    }
                }
            }
        })
    );
    Ok(())
}

const DOWNLOADS: &str = "https://reminders.example.com/downloads/";

/// A Chrome update check as managed Chrome sends it, one `x` per extension.
fn check_url(checks: &[(&str, &str, bool)]) -> String {
    let checks = checks
        .iter()
        .map(|(id, version, policy)| {
            let installed_by = if *policy {
                "%26installedby%3Dpolicy"
            } else {
                ""
            };
            format!(
                "&x=id%3D{id}%26v%3D{version}%26installsource%3Dnotfromwebstore{installed_by}%26uc"
            )
        })
        .collect::<String>();
    format!(
        "{DOWNLOADS}updates.xml?os=mac&arch=arm64&prod=chromecrx&prodchannel=&prodversion=157.0.8103.79&lang=en-US&acceptformat=crx3,puff{checks}"
    )
}

fn request(client: &str, url: impl Into<String>, status: u16) -> DownloadRequest {
    DownloadRequest {
        url: url.into(),
        status,
        client: client.into(),
    }
}

#[test]
fn fleet_reports_each_clients_latest_version_and_policy_checks() -> Result<()> {
    let release = pack_with(TEST_KEY, &source("1.1"), &Files::new())?.release;
    let requests = [
        request("198.51.100.1", check_url(&[(TEST_ID, "1.0", true)]), 200),
        request("198.51.100.1", format!("{DOWNLOADS}reminders.crx"), 200),
        request("198.51.100.1", check_url(&[(TEST_ID, "1.1", true)]), 200),
        request(
            "198.51.100.2",
            check_url(&[(OTHER_ID, "4.0", true), (TEST_ID, "1.0", true)]),
            200,
        ),
        request(
            "198.51.100.3",
            check_url(&[(TEST_ID, "0.0.0.0", true)]),
            200,
        ),
        request(
            "198.51.100.4",
            check_url(&[(TEST_ID, "1.1", false)]).replace("%3D", "%3d"),
            200,
        ),
        request("198.51.100.5", format!("{DOWNLOADS}updates.xml"), 200),
        request("198.51.100.6", format!("{DOWNLOADS}reminders.crx"), 304),
        request(
            "198.51.100.7",
            check_url(&[(TEST_ID, "9.0", true)])
                .replace("reminders.example.com", "other.example.com"),
            200,
        ),
        request("198.51.100.8", format!("{DOWNLOADS}notes.txt"), 500),
    ];
    let report = fleet(&release, &requests)?;
    assert_eq!(
        report,
        Fleet {
            extension_id: TEST_ID.into(),
            published_version: "1.1".into(),
            update_url: format!("{DOWNLOADS}updates.xml"),
            window_hours: FLEET_WINDOW_HOURS,
            update_checks: 5,
            policy_update_checks: 4,
            package_downloads: 1,
            server_errors: 0,
            clients_by_version: BTreeMap::from([
                ("0.0.0.0".into(), 1),
                ("1.0".into(), 1),
                ("1.1".into(), 2),
            ]),
            clients_on_published: 2,
            problems: Vec::new(),
        }
    );
    assert!(
        !serde_json::to_string(&report)?.contains("198.51.100."),
        "client addresses never appear in the report"
    );
    Ok(())
}

#[test]
fn fleet_flags_silence_edge_failures_and_browsers_ahead_of_the_release() -> Result<()> {
    let release = pack_with(TEST_KEY, &source("1.1"), &Files::new())?.release;
    let silent = fleet(&release, &[])?;
    assert_eq!(silent.problems, [FleetProblem::NoPolicyUpdateChecks]);
    assert_eq!(silent.clients_by_version, BTreeMap::new());

    let report = fleet(
        &release,
        &[
            request("a", check_url(&[(TEST_ID, "1.1", true)]), 502),
            request("b", check_url(&[(TEST_ID, "2.0", true)]), 200),
            request("c", check_url(&[(TEST_ID, "1.1.0", true)]), 200),
            request("c", format!("{DOWNLOADS}reminders.crx"), 503),
        ],
    )?;
    assert_eq!(
        report.problems,
        [
            FleetProblem::ServerErrors,
            FleetProblem::ClientsAheadOfRelease
        ]
    );
    assert_eq!(
        (
            report.update_checks,
            report.server_errors,
            report.package_downloads,
            report.clients_on_published,
        ),
        (3, 2, 0, 2),
        "1.1.0 is the published 1.1; a failed download is not an update"
    );
    assert_eq!(
        serde_json::to_value(FleetProblem::ClientsAheadOfRelease)?,
        json!("clients_ahead_of_release")
    );
    Ok(())
}
