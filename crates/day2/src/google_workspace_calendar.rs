//! Calendar reads for `GoogleWorkspace`: input validation, request shapes and
//! the strict parsing of Google's calendar, ACL and event responses into the
//! typed values an application receives. The pipeline in `google_workspace`
//! decides order, identity, bounds and classification.
use crate::google_workspace::Failure;
use serde::{Deserialize, Serialize};

pub const CALENDAR_READ_SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";
pub const CALENDAR_ACL_READ_SCOPE: &str = "https://www.googleapis.com/auth/calendar.acls.readonly";
/// One Calendar response: a calendar, an ACL page or an event page.
pub const MAX_CALENDAR_RESPONSE_BYTES: usize = 64 * 1024;
/// ACL entries requested per page, Google's maximum.
pub const ACL_PAGE_SIZE: u32 = 250;
/// ACL pages read before a calendar's sharing is refused as too large to
/// answer; the group's entry is never guessed from a partial list.
pub const ACL_PAGE_CEILING: u64 = 4;
/// Events per page. Every field is bounded below, so a full page of the
/// largest admissible events journals within one 64 KiB observation.
pub const EVENT_PAGE_SIZE: u32 = 25;
/// The longest window an events read may name.
pub const MAX_WINDOW_SECONDS: i64 = 31 * 86_400;
const MAX_ID_BYTES: usize = 1024;
const MAX_PAGE_TOKEN_BYTES: usize = 1024;
const MAX_SUMMARY_BYTES: usize = 1024;
const MAX_ADDRESS_BYTES: usize = 254;
/// The event fields read, as Google's partial-response mask.
pub const EVENT_FIELDS: &str = "id,originalStartTime,start,end,status,visibility,creator/email,\
    organizer/email,conferenceData/conferenceId,hangoutLink";

/// An optional value in the SDK's tag encoding: `"None"` or `{"Some": value}`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Text {
    None,
    Some(String),
}

impl Text {
    fn of(value: Option<String>) -> Self {
        value.map_or(Self::None, Self::Some)
    }

    pub fn into_option(self) -> Option<String> {
        match self {
            Self::None => None,
            Self::Some(value) => Some(value),
        }
    }
}

/// A calendar ID, exactly as accepted: lowercase ASCII, one `@`, a local part
/// of letters, digits and `._+-`, and a domain of lowercase labels. That covers
/// people's calendars and Google's group and resource calendar IDs, and every
/// accepted character is safe in a URL path segment.
pub fn calendar_id(value: &str) -> bool {
    value.len() <= MAX_ADDRESS_BYTES
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 128
                && local.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._+-".contains(&byte)
                })
                && !local.starts_with('.')
                && !local.ends_with('.')
                && !local.contains("..")
                && domain.split('.').count() >= 2
                && domain.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
        })
}

/// An event ID: Google's base32hex IDs, and recurring instances with their
/// `_YYYYMMDDTHHMMSSZ` suffix. ASCII letters, digits and `_` only.
pub fn event_id(value: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// An opaque page token, carried verbatim in a query parameter.
pub fn page_token(value: &str) -> bool {
    (1..=MAX_PAGE_TOKEN_BYTES).contains(&value.len())
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let month_prime = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * month_prime + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

fn digits(value: &str, range: std::ops::Range<usize>) -> Option<i64> {
    let part = value.get(range)?;
    part.bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| part.parse().ok())
        .flatten()
}

/// The day number of `YYYY-MM-DD`, or None if it is not exactly that.
pub fn date_days(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let (year, month, day) = (
        digits(value, 0..4)?,
        digits(value, 5..7)?,
        digits(value, 8..10)?,
    );
    ((1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day))
        .then(|| days_from_civil(year, month, day))
}

/// Seconds since the epoch of an RFC 3339 timestamp with whole seconds and an
/// explicit offset: `YYYY-MM-DDTHH:MM:SSZ` or `…±HH:MM`. Anything else, even a
/// valid RFC 3339 variant, is None.
pub fn rfc3339_seconds(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if !(20..=25).contains(&bytes.len())
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let days = date_days(value.get(0..10)?)?;
    let (hour, minute, second) = (
        digits(value, 11..13)?,
        digits(value, 14..16)?,
        digits(value, 17..19)?,
    );
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let offset = match value.get(19..)? {
        "Z" => 0,
        zone if zone.len() == 6 && zone.as_bytes()[3] == b':' => {
            let (hours, minutes) = (digits(value, 20..22)?, digits(value, 23..25)?);
            if hours > 23 || minutes > 59 {
                return None;
            }
            let magnitude = hours * 3_600 + minutes * 60;
            match zone.as_bytes()[0] {
                b'+' => magnitude,
                b'-' => -magnitude,
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

/// A read window: both bounds exact, increasing, and at most 31 days apart.
pub fn window(time_min: &str, time_max: &str) -> bool {
    match (rfc3339_seconds(time_min), rfc3339_seconds(time_max)) {
        (Some(min), Some(max)) => min < max && max - min <= MAX_WINDOW_SECONDS,
        _ => false,
    }
}

/// A Meet code: three, four and three lowercase letters.
pub fn meeting_code(value: &str) -> bool {
    let parts: Vec<_> = value.split('-').collect();
    parts.len() == 3
        && [3, 4, 3].iter().zip(&parts).all(|(length, part)| {
            part.len() == *length && part.bytes().all(|byte| byte.is_ascii_lowercase())
        })
}

/// The Meet code of `https://meet.google.com/{code}` exactly.
fn hangout_code(link: &str) -> Option<String> {
    let code = link.strip_prefix("https://meet.google.com/")?;
    meeting_code(code).then(|| code.to_owned())
}

/// The role a calendar's ACL gives one group.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum GroupRole {
    None,
    FreeBusyReader,
    Reader,
    Writer,
    Owner,
}

impl GroupRole {
    fn from_google(role: &str) -> Result<Self, Failure> {
        Ok(match role {
            "none" => Self::None,
            "freeBusyReader" => Self::FreeBusyReader,
            "reader" => Self::Reader,
            "writer" => Self::Writer,
            "owner" => Self::Owner,
            _ => return Err(Failure::ResponseInvalid),
        })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Calendar {
    pub id: String,
    pub summary: String,
    pub group_role: GroupRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalendarOutcome {
    Found(Calendar),
    NotFound,
}

impl CalendarOutcome {
    pub fn encode(&self) -> String {
        match self {
            Self::Found(calendar) => serde_json::json!({ "Found": calendar }).to_string(),
            Self::NotFound => serde_json::json!("NotFound").to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum EventStatus {
    Confirmed,
    Tentative,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Visibility {
    Default,
    Public,
    Private,
    Confidential,
}

/// A timed event as an application receives it. `start` and `end` are absent
/// only on a cancelled event, which Google may report without its times.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub status: EventStatus,
    pub visibility: Visibility,
    pub start: Text,
    pub end: Text,
    pub original_start: Text,
    pub organizer: Text,
    pub creator: Text,
    pub meeting_code: Text,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EventsPage {
    pub events: Vec<Event>,
    pub next_page_token: Text,
    /// All-day events on this page, which carry no time and are omitted.
    pub all_day_omitted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventsOutcome {
    Found(EventsPage),
    NotFound,
}

impl EventsOutcome {
    pub fn encode(&self) -> String {
        match self {
            Self::Found(page) => serde_json::json!({ "Found": page }).to_string(),
            Self::NotFound => serde_json::json!("NotFound").to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventOutcome {
    Found(Event),
    /// The event exists but is all-day, so it has no time to report.
    AllDay,
    NotFound,
}

impl EventOutcome {
    pub fn encode(&self) -> String {
        match self {
            Self::Found(event) => serde_json::json!({ "Found": event }).to_string(),
            Self::AllDay => serde_json::json!("AllDay").to_string(),
            Self::NotFound => serde_json::json!("NotFound").to_string(),
        }
    }
}

/// The calendar's id and summary. The id must be the calendar that was asked for.
pub fn parse_calendar(body: &[u8], expected: &str) -> Result<(String, String), Failure> {
    #[derive(Deserialize)]
    struct CalendarDto {
        id: String,
        #[serde(default)]
        summary: String,
    }
    let calendar: CalendarDto = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if !calendar.id.eq_ignore_ascii_case(expected)
        || calendar.summary.len() > MAX_SUMMARY_BYTES
        || calendar.summary.chars().any(char::is_control)
    {
        return Err(Failure::ResponseInvalid);
    }
    Ok((expected.to_owned(), calendar.summary))
}

/// One ACL page: the named group's role if this page has its entry, and the
/// continuation. Addresses are case-insensitive to Google, so the entry's value
/// is compared ignoring ASCII case; nothing else is read or returned.
pub fn parse_acl_page(
    body: &[u8],
    group: &str,
) -> Result<(Option<GroupRole>, Option<String>), Failure> {
    #[derive(Deserialize)]
    struct Scope {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        value: Option<String>,
    }
    #[derive(Deserialize)]
    struct Rule {
        scope: Scope,
        role: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AclPage {
        #[serde(default)]
        items: Vec<Rule>,
        next_page_token: Option<String>,
    }
    let page: AclPage = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if page.items.len() > ACL_PAGE_SIZE as usize
        || page
            .next_page_token
            .as_deref()
            .is_some_and(|token| !page_token(token))
    {
        return Err(Failure::ResponseInvalid);
    }
    for rule in page.items {
        let role = GroupRole::from_google(&rule.role)?;
        if rule.scope.kind == "group"
            && rule
                .scope
                .value
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(group))
        {
            return Ok((Some(role), None));
        }
    }
    Ok((None, page.next_page_token))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TimeDto {
    date_time: Option<String>,
    date: Option<String>,
}

#[derive(Deserialize)]
struct PersonDto {
    email: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConferenceDto {
    conference_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventDto {
    id: String,
    status: Option<String>,
    visibility: Option<String>,
    start: Option<TimeDto>,
    end: Option<TimeDto>,
    original_start_time: Option<TimeDto>,
    creator: Option<PersonDto>,
    organizer: Option<PersonDto>,
    conference_data: Option<ConferenceDto>,
    hangout_link: Option<String>,
}

/// What one reported event becomes.
enum Parsed {
    Timed(Event),
    AllDay,
}

fn address(person: Option<PersonDto>) -> Result<Text, Failure> {
    match person.and_then(|person| person.email) {
        None => Ok(Text::None),
        Some(email)
            if (3..=MAX_ADDRESS_BYTES).contains(&email.len())
                && email.contains('@')
                && email.bytes().all(|byte| byte.is_ascii_graphic()) =>
        {
            Ok(Text::Some(email))
        }
        Some(_) => Err(Failure::ResponseInvalid),
    }
}

/// A timed value: a validated `dateTime`, or None when the time is absent.
fn timed(time: Option<TimeDto>) -> Result<Option<String>, Failure> {
    match time {
        None => Ok(None),
        Some(TimeDto {
            date_time: Some(value),
            date: None,
        }) if rfc3339_seconds(&value).is_some() => Ok(Some(value)),
        Some(_) => Err(Failure::ResponseInvalid),
    }
}

fn all_day(time: &Option<TimeDto>) -> bool {
    matches!(
        time,
        Some(TimeDto {
            date_time: None,
            date: Some(date),
        }) if date_days(date).is_some()
    )
}

fn event(dto: EventDto) -> Result<Parsed, Failure> {
    if !event_id(&dto.id) {
        return Err(Failure::ResponseInvalid);
    }
    let status = match dto.status.as_deref() {
        Some("confirmed") => EventStatus::Confirmed,
        Some("tentative") => EventStatus::Tentative,
        Some("cancelled") => EventStatus::Cancelled,
        _ => return Err(Failure::ResponseInvalid),
    };
    let visibility = match dto.visibility.as_deref() {
        None | Some("default") => Visibility::Default,
        Some("public") => Visibility::Public,
        Some("private") => Visibility::Private,
        Some("confidential") => Visibility::Confidential,
        Some(_) => return Err(Failure::ResponseInvalid),
    };
    if all_day(&dto.start) {
        return Ok(Parsed::AllDay);
    }
    let start = timed(dto.start)?;
    let end = timed(dto.end)?;
    // Only a cancelled event may be reported without its times.
    if status != EventStatus::Cancelled && (start.is_none() || end.is_none()) {
        return Err(Failure::ResponseInvalid);
    }
    if let (Some(start), Some(end)) = (&start, &end)
        && rfc3339_seconds(start) > rfc3339_seconds(end)
    {
        return Err(Failure::ResponseInvalid);
    }
    let original_start = if all_day(&dto.original_start_time) {
        None
    } else {
        timed(dto.original_start_time)?
    };
    let meeting_code = dto
        .conference_data
        .and_then(|conference| conference.conference_id)
        .filter(|code| meeting_code(code))
        .or_else(|| dto.hangout_link.as_deref().and_then(hangout_code));
    Ok(Parsed::Timed(Event {
        id: dto.id,
        status,
        visibility,
        start: Text::of(start),
        end: Text::of(end),
        original_start: Text::of(original_start),
        organizer: address(dto.organizer)?,
        creator: address(dto.creator)?,
        meeting_code: Text::of(meeting_code),
    }))
}

/// One events page. A page larger than the requested size, an invalid
/// continuation, or a page that would not journal within one observation is
/// refused rather than truncated.
pub fn parse_events_page(body: &[u8]) -> Result<EventsPage, Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        #[serde(default)]
        items: Vec<EventDto>,
        next_page_token: Option<String>,
    }
    let page: Page = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if page.items.len() > EVENT_PAGE_SIZE as usize
        || page
            .next_page_token
            .as_deref()
            .is_some_and(|token| !page_token(token))
    {
        return Err(Failure::ResponseInvalid);
    }
    let mut events = Vec::new();
    let mut all_day_omitted = 0;
    for item in page.items {
        match event(item)? {
            Parsed::Timed(event) => events.push(event),
            Parsed::AllDay => all_day_omitted += 1,
        }
    }
    let page = EventsPage {
        events,
        next_page_token: Text::of(page.next_page_token),
        all_day_omitted,
    };
    let encoded = EventsOutcome::Found(page.clone()).encode();
    match crate::capture_delivery::journal_bytes(&encoded) {
        Ok(bytes) if bytes <= crate::capture_delivery::MAX_PAGE_JOURNAL_BYTES => Ok(page),
        _ => Err(Failure::ResponseTooLarge),
    }
}

/// One event, as `events.get` reports it.
pub fn parse_event(body: &[u8], expected: &str) -> Result<EventOutcome, Failure> {
    let dto: EventDto = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if dto.id != expected {
        return Err(Failure::ResponseInvalid);
    }
    Ok(match event(dto)? {
        Parsed::Timed(event) => EventOutcome::Found(event),
        Parsed::AllDay => EventOutcome::AllDay,
    })
}
