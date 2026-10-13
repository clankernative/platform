//! Closed read-only Calendar adapter. Provider cursors, URLs and tokens stay
//! native. A Listed outcome always covers the complete admitted window.
use super::{custody::AccessToken, effects};
use anyhow::Result;
use reqwest::{header::CONTENT_TYPE, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeSet, io::Read, time::Duration};
use time::{Date, OffsetDateTime, format_description::well_known::Rfc3339};

const ENDPOINT: &str = "https://www.googleapis.com/calendar/v3/calendars/primary/events";
const MAX_PAGES: usize = 4;
const MAX_EVENTS: usize = 100;
const MAX_BODY: usize = 128 * 1024;
// The preparation journal JSON-escapes this complete JSON result once more.
// Leave enough space for its instruction/envelope under the 64 KiB frame cap.
const MAX_RESULT: usize = 30 * 1024;
const MAX_SECONDS: u64 = 8;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Window {
    pub start: String,
    pub end: String,
}

impl Window {
    pub(super) fn valid(&self) -> bool {
        if self.start.len() > 64 || self.end.len() > 64 {
            return false;
        }
        let (Ok(start), Ok(end)) = (
            OffsetDateTime::parse(&self.start, &Rfc3339),
            OffsetDateTime::parse(&self.end, &Rfc3339),
        ) else {
            return false;
        };
        let span = end - start;
        start.unix_timestamp() >= 0
            && start.nanosecond() == 0
            && end.nanosecond() == 0
            && span.is_positive()
            && span <= time::Duration::days(31)
    }
}

#[derive(Serialize)]
struct Event {
    id: String,
    summary: String,
    start: String,
    end: String,
    all_day: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Page {
    #[serde(default)]
    items: Vec<WireEvent>,
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvent {
    id: String,
    #[serde(default)]
    summary: String,
    start: EventTime,
    end: EventTime,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventTime {
    date: Option<String>,
    date_time: Option<String>,
}

impl WireEvent {
    fn decode(self) -> Result<Event> {
        anyhow::ensure!(
            !self.id.is_empty() && self.id.len() <= 128 && self.summary.len() <= 256,
            "Calendar event byte budget"
        );
        let (start, end, all_day) = match (
            self.start.date,
            self.start.date_time,
            self.end.date,
            self.end.date_time,
        ) {
            (Some(start), None, Some(end), None) => {
                let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")?;
                anyhow::ensure!(
                    start.len() == 10
                        && end.len() == 10
                        && Date::parse(&end, &format)? > Date::parse(&start, &format)?,
                    "invalid Calendar all-day bounds"
                );
                (start, end, true)
            }
            (None, Some(start), None, Some(end)) => {
                anyhow::ensure!(
                    start.len() <= 64
                        && end.len() <= 64
                        && OffsetDateTime::parse(&end, &Rfc3339)?
                            > OffsetDateTime::parse(&start, &Rfc3339)?,
                    "invalid Calendar event bounds"
                );
                (start, end, false)
            }
            _ => anyhow::bail!("invalid Calendar event time representation"),
        };
        Ok(Event {
            id: self.id,
            summary: self.summary,
            start,
            end,
            all_day,
        })
    }
}

fn unavailable(problem: &str) -> String {
    json!({"Unavailable": problem}).to_string()
}

// https://developers.google.com/workspace/calendar/api/v3/reference/events/list
// singleEvents expands recurring events; startTime ordering requires it. An
// empty page with nextPageToken is incomplete and must still be followed.
pub(super) fn list(token: &AccessToken, window: &Window) -> Result<String> {
    anyhow::ensure!(window.valid(), "invalid Calendar window");
    let client = effects::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()?;
    let started = effects::Instant::now();
    let mut page_token = None::<String>;
    let mut tokens = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut events = Vec::new();
    for _ in 0..MAX_PAGES {
        let elapsed = started.elapsed();
        if elapsed >= Duration::from_secs(MAX_SECONDS) {
            return Ok(unavailable("CapacityDeferred"));
        }
        let mut url = url::Url::parse(ENDPOINT)?;
        url.query_pairs_mut().extend_pairs([
            ("timeMin", window.start.as_str()),
            ("timeMax", window.end.as_str()),
            ("singleEvents", "true"),
            ("orderBy", "startTime"),
            ("showDeleted", "false"),
            ("maxResults", "100"),
            (
                "fields",
                "items(id,summary,start(date,dateTime),end(date,dateTime)),nextPageToken",
            ),
        ]);
        if let Some(cursor) = &page_token {
            url.query_pairs_mut().append_pair("pageToken", cursor);
        }
        let response = match client
            .get(url)
            .header(reqwest::header::AUTHORIZATION, token.authorization()?)
            .timeout(Duration::from_secs(3).min(Duration::from_secs(MAX_SECONDS) - elapsed))
            .send()
        {
            Ok(response) => response,
            Err(_) => return Ok(unavailable("ProviderUnavailable")),
        };
        let problem = match response.status().as_u16() {
            200 => None,
            401 => Some("ReauthRequired"),
            403 => Some("PermissionDenied"),
            429 => Some("CapacityDeferred"),
            _ => Some("ProviderUnavailable"),
        };
        if let Some(problem) = problem {
            return Ok(unavailable(problem));
        }
        if !response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.split(';').next() == Some("application/json"))
            || response
                .content_length()
                .is_some_and(|length| length > MAX_BODY as u64)
        {
            return Ok(unavailable("ProviderUnavailable"));
        }
        let mut bytes = Vec::new();
        if response
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() > MAX_BODY
        {
            return Ok(unavailable("ProviderUnavailable"));
        }
        let page = match crate::json::decode::<Page>(&bytes) {
            Ok(page) if page.items.len() <= MAX_EVENTS => page,
            _ => return Ok(unavailable("ProviderUnavailable")),
        };
        for event in page.items {
            let event = match event.decode() {
                Ok(event) => event,
                Err(_) => return Ok(unavailable("ProviderUnavailable")),
            };
            if !ids.insert(event.id.clone()) {
                return Ok(unavailable("ProviderUnavailable"));
            }
            events.push(event);
            if events.len() > MAX_EVENTS {
                return Ok(unavailable("CapacityDeferred"));
            }
        }
        let encoded = json!({"Listed": &events}).to_string();
        if encoded.len() > MAX_RESULT {
            return Ok(unavailable("CapacityDeferred"));
        }
        match page.next_page_token {
            None => return Ok(encoded),
            Some(cursor)
                if !cursor.is_empty()
                    && cursor.len() <= 2048
                    && !cursor.chars().any(char::is_control)
                    && tokens.insert(cursor.clone()) =>
            {
                page_token = Some(cursor)
            }
            _ => return Ok(unavailable("ProviderUnavailable")),
        }
    }
    Ok(unavailable("CapacityDeferred"))
}
