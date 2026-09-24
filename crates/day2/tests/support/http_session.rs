//! Real local sign-in and cookie/CSRF transport for native HTTP acceptance tests.
use anyhow::{Context, Result};
use day2::{store::Runtime, web::LocalServer};
use reqwest::{
    StatusCode,
    blocking::{Client, RequestBuilder, Response},
    redirect::Policy,
};
use scraper::{Html, Selector};
use serde_json::Value;
use std::{collections::BTreeMap, sync::mpsc, thread, time::Duration};

pub struct Session {
    pub origin: String,
    pub client: Client,
    csrf: String,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<Result<()>>>,
}

impl Session {
    pub fn start(runtime: Runtime, actor: &str) -> Result<Self> {
        let actor = actor.to_owned();
        let (send, receive) = mpsc::channel();
        let (stop, done) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?
                .block_on(async move {
                    let server = LocalServer::bind(runtime, &actor, 0).await?;
                    send.send((server.origin.clone(), server.login_url.clone()))?;
                    server
                        .serve(async {
                            let _ = done.await;
                        })
                        .await
                })
        });
        let (origin, login) = receive.recv_timeout(Duration::from_secs(10))?;
        let mut session = Self {
            origin,
            client: Client::builder()
                .cookie_store(true)
                .redirect(Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            csrf: String::new(),
            stop: Some(stop),
            thread: Some(thread),
        };
        let response = session.client.get(login).send()?;
        assert_eq!(response.status(), StatusCode::OK);
        let document = Html::parse_document(&response.text()?);
        let fields: BTreeMap<String, String> = document
            .select(&Selector::parse("form input[name]").unwrap())
            .map(|field| {
                (
                    field.value().attr("name").unwrap().into(),
                    field.value().attr("value").unwrap_or("").into(),
                )
            })
            .collect();
        assert_eq!(
            session
                .client
                .post(format!("{}/login", session.origin))
                .header("Origin", &session.origin)
                .form(&fields)
                .send()?
                .status(),
            StatusCode::SEE_OTHER
        );
        let result = value(session.get("/api/session").send()?, StatusCode::OK)?;
        session.csrf = result["csrf_token"]
            .as_str()
            .context("session CSRF token")?
            .into();
        Ok(session)
    }

    pub fn get(&self, path: &str) -> RequestBuilder {
        self.client.get(format!("{}{path}", self.origin))
    }

    pub fn acting_get(&self, path: &str, actor: &str) -> RequestBuilder {
        self.get(path)
            .header("X-Day2-Act-As", actor)
            .header("Origin", &self.origin)
            .header("X-CSRF-Token", &self.csrf)
    }

    pub fn post(&self, operation: &str, key: &str, input: &Value) -> RequestBuilder {
        self.client
            .post(format!("{}/api/{operation}", self.origin))
            .header("Origin", &self.origin)
            .header("X-CSRF-Token", &self.csrf)
            .header("Idempotency-Key", key)
            .header("Content-Type", "application/json")
            .body(input.to_string())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !thread::panicking() {
                assert!(result.expect("HTTP server thread").is_ok());
            }
        }
    }
}

pub fn value(response: Response, expected: StatusCode) -> Result<Value> {
    let status = response.status();
    let body = response.text()?;
    assert_eq!(status, expected, "{body}");
    Ok(serde_json::from_str(&body)?)
}
