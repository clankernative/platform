//! The trusted shell is the only document that can fetch the fixed query.
//! The opaque child receives a MessagePort and its own inline-only policy.
const SHELL_SCRIPT: &str = include_str!("../../../assets/prototype-shell.js");
const FRAME_SCRIPT: &str = include_str!("../../../assets/prototype-frame.js");

const SHELL_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'";
const FRAME_CSP: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; worker-src 'none'";
const SHELL_STYLE: &str = "html,body{height:100%;margin:0}body{display:flex;flex-direction:column;font:15px system-ui,sans-serif;color:#20262c}nav{display:flex;align-items:center;justify-content:space-between;padding:.6rem 1rem;border-bottom:1px solid #d5dce0}iframe{display:block;flex:1;min-height:0;width:100%;border:none}p{margin:1rem}details{padding:.5rem 1rem;border-bottom:1px solid #d5dce0}summary{cursor:pointer}textarea{display:block;box-sizing:border-box;width:100%;height:clamp(8rem,28vh,24rem);margin:.6rem 0;font:14px/1.4 ui-monospace,monospace}button{padding:.4rem .8rem}#save-status{margin-left:.75rem}";

pub(crate) fn shell(
    frame_url: &str,
    query_url: &str,
    operation: &str,
    source_url: Option<&str>,
    editor: Option<(&str, &str)>,
) -> (String, String) {
    let body = maud::html! {
        (maud::DOCTYPE)
        html lang="en" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { "Day2 prototype" }
                style { (maud::PreEscaped(SHELL_STYLE)) }
            }
            body {
                nav aria-label="Prototype" {
                    span { "Day2 prototype" }
                    @if let Some(url) = source_url {
                        a href=(url) download { "Download source" }
                    }
                }
                @if let Some((save_command, current_html)) = editor {
                    details id="editor" data-save-command=(save_command) {
                        summary { "Edit HTML" }
                        // A leading newline is stripped by the HTML textarea parser.
                        textarea aria-label="Prototype HTML" spellcheck="false" { "\n" (current_html) }
                        button id="save" type="button" { "Save & preview" }
                        span id="save-status" role="status" {}
                    }
                }
                p id="load-status" role="status" { "Loading prototype…" }
                iframe title="Prototype" sandbox="allow-scripts" referrerpolicy="no-referrer" {}
                script data-frame=(frame_url) data-query=(query_url) data-operation=(operation) {
                    (maud::PreEscaped(SHELL_SCRIPT))
                }
            }
        }
    };
    (body.into_string(), SHELL_CSP.to_owned())
}

pub(crate) fn frame(html: &str, operation: &str) -> (String, String) {
    // Prepend before *all* authored bytes. Response headers protect a direct
    // visit; srcdoc needs the meta policy because it inherits the shell CSP.
    let bootstrap = maud::html! {
        (maud::DOCTYPE)
        meta charset="utf-8";
        meta http-equiv="Content-Security-Policy" content=(FRAME_CSP);
        script data-operation=(operation) { (maud::PreEscaped(FRAME_SCRIPT)) }
    };
    let mut body = bootstrap.into_string();
    body.push_str(html);
    (
        body,
        format!("{FRAME_CSP}; sandbox allow-scripts; frame-ancestors 'none'"),
    )
}

#[cfg(test)]
mod tests;
