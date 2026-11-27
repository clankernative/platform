use super::{Submission, frame, shell};
use std::{fs, process::Command};

#[test]
fn documents_keep_source_grants_and_credentials_outside_authored_html() {
    let (shell_html, shell_policy) = shell(
        "/frame?pin=one",
        "/query?pin=one",
        "history",
        None,
        None,
        None,
    );
    assert!(shell_html.contains(r#"sandbox="allow-scripts""#));
    assert!(!shell_html.contains("allow-same-origin"));
    assert!(!shell_html.contains("Download source"));
    assert!(shell_policy.contains("frame-src 'none'"));
    let (owner_html, _) = shell(
        "/frame",
        "/query",
        "history",
        Some("/source?pin=one"),
        Some(("app.save", "</textarea><script>secret_source</script>")),
        None,
    );
    assert!(owner_html.contains(r#"href="/source?pin=one" download"#));

    assert!(owner_html.contains("&lt;/textarea&gt;"));
    assert!(!owner_html.contains("<script>secret_source</script>"));
    assert!(!shell_html.contains(r#"id="editor""#));

    let authored = "<!doctype html><script>window.example = 1</script>";
    let (frame_html, frame_policy) = frame(authored, "history", None);
    assert!(frame_html.ends_with(authored));
    assert!(frame_html[..frame_html.len() - authored.len()].contains("Content-Security-Policy"));
    assert!(!frame_html.contains("/query"));
    assert!(!frame_html.contains("X-Day2-Prototype-Query"));
    for directive in [
        "connect-src 'none'",
        "frame-src 'none'",
        "sandbox allow-scripts",
    ] {
        assert!(frame_policy.contains(directive));
    }
}

// Real browser fixture with the rendered production documents and synthetic
// responses. Node supplies only the HTTP fixture and the DevTools test driver.
#[test]
#[ignore = "requires local Node and Chromium; set CHROME_BINARY if needed"]
fn chromium_keeps_the_query_inside_the_original_opaque_frame() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = temp.path().join("documents.json");
    let driver = temp.path().join("browser.test.mjs");
    let documents = serde_json::json!({
        "shell": shell("/frame?pin=one", "/query?pin=one", "history", None, None, None),
        "editor": shell("/frame?pin=one", "/query?pin=one", "history", Some("/source"), Some(("app.save", "<p>draft</p>")), None),
        "submitShell": shell("/submit-frame?pin=one", "/query?pin=one", "history", None, None, Some(Submission {
            operation:"app.submit_request", url:"/submit?pin=one",
            fields:r#"{"amount":"integer","ok":"boolean","vendor":"string"}"#.into()
        })),
        "submitFrame": frame(r#"<button id="propose" type="button" style="position:fixed;top:0;left:0;width:120px;height:48px">Submit sample</button><script>/* SUBMIT_PROBE */</script>"#,
            "history", Some("submit_request")),
        "frame": frame("<script>/* TEST_PROBE */</script>", "history", None),
    });
    fs::write(&fixture, documents.to_string()).unwrap();
    fs::write(&driver, include_str!("browser.test.mjs")).unwrap();
    let status = Command::new("node")
        .arg(driver)
        .arg(fixture)
        .status()
        .unwrap();
    assert!(status.success());
}
