//! HTTP client samples generated from the same OpenAPI operations as the UI.
use serde_json::{Value, json};

pub fn populate(document: &mut Value) {
    let origin = document["servers"][0]["url"]
        .as_str()
        .unwrap_or("http://localhost:8080")
        .to_string();
    for (path, methods) in document["paths"].as_object_mut().expect("OpenAPI paths") {
        for (method, operation) in methods.as_object_mut().expect("OpenAPI methods") {
            operation["x-codeSamples"] = samples(&origin, path, method, operation);
        }
    }
}

fn quoted(text: &str) -> String {
    serde_json::to_string(text).expect("JSON string")
}
fn shell(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}
fn java(text: &str) -> String {
    let mut result = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            ch if ch.is_ascii_control() => result.push_str(&format!("\\{:03o}", ch as u32)),
            ch => result.push(ch),
        }
    }
    result.push('"');
    result
}

fn samples(origin: &str, path: &str, method: &str, operation: &Value) -> Value {
    let method = method.to_uppercase();
    let command = method == "POST";
    let mut url = format!("{}{path}", origin.trim_end_matches('/'));
    if !command {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(parameters) = operation["parameters"].as_array() {
            for parameter in parameters
                .iter()
                .filter(|parameter| parameter["in"] == "path")
            {
                let name = parameter["name"].as_str().expect("parameter name");
                let value = parameter["example"].as_str().unwrap_or("INVOCATION_ID");
                let encoded =
                    url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
                url = url.replace(&format!("{{{name}}}"), &encoded);
            }
            for parameter in parameters
                .iter()
                .filter(|parameter| parameter["in"] == "query")
            {
                let value = if parameter.get("content").is_some() {
                    parameter["content"]["application/json"]["example"].to_string()
                } else {
                    parameter["example"]
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| parameter["example"].to_string())
                };
                query.append_pair(parameter["name"].as_str().expect("parameter name"), &value);
            }
        }
        let query = query.finish();
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query);
        }
    }
    let body = serde_json::to_string_pretty(
        &operation["requestBody"]["content"]["application/json"]["example"],
    )
    .expect("example");
    // Environment references are instructions for the reader, never embedded credentials.
    let mut headers = vec![
        ("Cookie", "DAY2_SESSION_COOKIE", true),
        ("Accept", "application/json", false),
    ];
    if command {
        headers.extend([
            ("Content-Type", "application/json", false),
            ("Origin", origin, false),
            ("X-CSRF-Token", "DAY2_CSRF_TOKEN", true),
            ("Idempotency-Key", "DAY2_IDEMPOTENCY_KEY", true),
        ]);
    }
    let mut curl = format!("curl --request {method} \\\n  --url {}", shell(&url));
    for (name, value, env) in &headers {
        let value = if *env {
            format!("\"{name}: ${{{value}:?Set {value}}}\"")
        } else {
            shell(&format!("{name}: {value}"))
        };
        curl.push_str(&format!(" \\\n  --header {value}"));
    }
    if command {
        curl.push_str(&format!(" \\\n  --data-raw {}", shell(&body)));
    }

    let js_headers = headers
        .iter()
        .map(|(name, value, env)| {
            format!(
                "    {}: {}",
                quoted(name),
                if *env {
                    format!("process.env.{value}")
                } else {
                    quoted(value)
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let js_body = if command {
        format!(",\n  body: {}", quoted(&body))
    } else {
        String::new()
    };
    let js = format!(
        "// Node.js 20+; print raw JSON to preserve 64-bit integer precision.\nconst response = await fetch({}, {{\n  method: {},\n  headers: {{\n{js_headers}\n  }}{js_body}\n}});\nconsole.log(response.status, await response.text());",
        quoted(&url),
        quoted(&method)
    );

    let py_headers = headers
        .iter()
        .map(|(name, value, env)| {
            format!(
                "    {}: {}",
                quoted(name),
                if *env {
                    format!("os.environ[{}]", quoted(value))
                } else {
                    quoted(value)
                }
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    let py_body = if command {
        format!(",\n    data={}.encode(\"utf-8\")", quoted(&body))
    } else {
        String::new()
    };
    let python = format!(
        "import os\nimport urllib.request\nimport urllib.error\n\nheaders = {{\n{py_headers}\n}}\nrequest = urllib.request.Request(\n    {}, headers=headers, method={}{py_body}\n)\ntry:\n    with urllib.request.urlopen(request, timeout=30) as response:\n        print(response.status, response.read().decode(\"utf-8\"))\nexcept urllib.error.HTTPError as error:\n    print(error.code, error.read().decode(\"utf-8\"))",
        quoted(&url),
        quoted(&method)
    );

    let go_headers = headers
        .iter()
        .map(|(name, value, env)| {
            format!(
                "    req.Header.Set({}, {})",
                quoted(name),
                if *env {
                    format!("os.Getenv({})", quoted(value))
                } else {
                    quoted(value)
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let go_body = if command {
        format!("strings.NewReader({})", quoted(&body))
    } else {
        "nil".into()
    };
    let go = format!(
        "package main\n\nimport (\n    \"fmt\"\n    \"io\"\n    \"net/http\"\n    \"os\"\n    \"time\"{}\n)\n\nfunc main() {{\n    req, err := http.NewRequest({}, {}, {go_body})\n    if err != nil {{ panic(err) }}\n{go_headers}\n    client := &http.Client{{Timeout: 30 * time.Second}}\n    response, err := client.Do(req)\n    if err != nil {{ panic(err) }}\n    defer response.Body.Close()\n    body, err := io.ReadAll(response.Body)\n    if err != nil {{ panic(err) }}\n    fmt.Println(response.StatusCode, string(body))\n}}",
        if command { "\n    \"strings\"" } else { "" },
        quoted(&method),
        quoted(&url)
    );

    let java_headers = headers
        .iter()
        .map(|(name, value, env)| {
            format!(
                "            .header({}, {})",
                java(name),
                if *env {
                    format!("System.getenv({})", java(value))
                } else {
                    java(value)
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let java_body = if command {
        format!(
            ".POST(HttpRequest.BodyPublishers.ofString({}, StandardCharsets.UTF_8))",
            java(&body)
        )
    } else {
        ".GET()".into()
    };
    let java_source = format!(
        "import java.net.URI;\nimport java.net.http.*;\nimport java.nio.charset.StandardCharsets;\nimport java.time.Duration;\n\npublic class Example {{\n    public static void main(String[] args) throws Exception {{\n        var client = HttpClient.newHttpClient();\n        var request = HttpRequest.newBuilder(URI.create({}))\n            .timeout(Duration.ofSeconds(30))\n{java_headers}\n            {java_body}\n            .build();\n        var response = client.send(request, HttpResponse.BodyHandlers.ofString());\n        System.out.println(response.statusCode());\n        System.out.println(response.body());\n    }}\n}}",
        java(&url)
    );

    let cs_headers = headers
        .iter()
        .filter(|(name, _, _)| *name != "Content-Type")
        .map(|(name, value, env)| {
            format!(
                "request.Headers.Add({}, {});",
                quoted(name),
                if *env {
                    format!("Environment.GetEnvironmentVariable({})!", quoted(value))
                } else {
                    quoted(value)
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let cs_body = if command {
        format!(
            "\nrequest.Content = new StringContent({}, Encoding.UTF8, \"application/json\");",
            quoted(&body)
        )
    } else {
        String::new()
    };
    let csharp = format!(
        "// .NET 8+ console application\nusing System;\nusing System.Net.Http;\nusing System.Text;\n\nusing var client = new HttpClient {{ Timeout = TimeSpan.FromSeconds(30) }};\nusing var request = new HttpRequestMessage(HttpMethod.{}, {});\n{cs_headers}{cs_body}\nusing var response = await client.SendAsync(request);\nConsole.WriteLine((int)response.StatusCode);\nConsole.WriteLine(await response.Content.ReadAsStringAsync());",
        if command { "Post" } else { "Get" },
        quoted(&url)
    );

    json!([
        {"lang":"Shell","label":"cURL","source":curl},
        {"lang":"JavaScript","label":"JavaScript","source":js},
        {"lang":"Python","label":"Python","source":python},
        {"lang":"Go","label":"Go","source":go},
        {"lang":"Java","label":"Java","source":java_source},
        {"lang":"CSharp","label":"C# / .NET","source":csharp},
    ])
}
