//! Calendar reads for `GoogleWorkspace`: input validation, the reviewed request
//! constants, and the strict parsing of Google's calendar, ACL and event
//! responses into the closed values an application receives. The pipeline in
//! `google_workspace` decides order, identity, bounds and classification.
use crate::carta::OptionalText;
use crate::google_workspace::Failure;
use serde::{Deserialize, Serialize};

pub const CALENDAR_READ_SCOPE: &str = "https://www.googleapis.com/auth/calendar.readonly";
pub const CALENDAR_ACL_READ_SCOPE: &str = "https://www.googleapis.com/auth/calendar.acls.readonly";
/// One Calendar response: a calendar, an ACL rule or page, or an event page.
pub const MAX_CALENDAR_RESPONSE_BYTES: usize = 64 * 1024;
/// ACL entries requested per page. The largest rule Google can report under
/// the fixed mask, compact, is 315 bytes (a 254-byte address and the
/// `freeBusyReader` role), so a full page with the longest token is 32,654
/// bytes: half the Calendar response bound. Google's own maximum, 250, could
/// reach 80,054 bytes. A test proves the page fits.
pub const ACL_PAGE_SIZE: u32 = 100;
/// ACL pages read before a calendar's sharing is refused as too large to
/// answer, 400 rules when Google fills each page; the group's entry is never
/// guessed from a partial list. Each page is one reserved call.
pub const ACL_PAGE_CEILING: u64 = 4;
/// Events per page. With every field bounded to characters JSON never escapes,
/// 25 of the largest admissible events journal within one observation; a test
/// proves it against `resources::bounded_observation`.
pub const EVENT_PAGE_SIZE: u32 = 25;
/// The longest window an events read may name.
pub const MAX_WINDOW_SECONDS: i64 = 31 * 86_400;
pub(crate) const MAX_ID_BYTES: usize = 1024;
pub(crate) const MAX_PAGE_TOKEN_BYTES: usize = 1024;
const MAX_SUMMARY_BYTES: usize = 1024;
pub(crate) const MAX_ADDRESS_BYTES: usize = 254;

macro_rules! event_fields {
    () => {
        "id,originalStartTime,start,end,status,visibility,creator/email,organizer/email,\
         conferenceData(conferenceId,conferenceSolution/key/type),hangoutLink"
    };
}
/// The event fields read, as Google's partial-response mask.
pub const EVENT_FIELDS: &str = event_fields!();
/// The events list mask: the event fields of every item and the continuation.
pub const EVENTS_FIELDS: &str = concat!("items(", event_fields!(), "),nextPageToken");
pub const CALENDAR_FIELDS: &str = "id,summary";
pub const ACL_FIELDS: &str = "items(scope(type,value),role),nextPageToken";
pub const RULE_FIELDS: &str = "scope(type,value),role";
/// The events list query, fixed except for the window and continuation.
pub const EVENTS_QUERY: [(&str, &str); 4] = [
    ("singleEvents", "true"),
    ("orderBy", "startTime"),
    ("showDeleted", "true"),
    ("maxResults", "25"),
];
/// Google's 403 reasons that mean a rate or quota was reached, not that access
/// was refused: the legacy `errors[].reason` values, and the `ErrorInfo`
/// reason newer APIs give.
pub const RATE_REASONS: [&str; 5] = [
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "quotaExceeded",
    "dailyLimitExceeded",
    "RATE_LIMIT_EXCEEDED",
];

fn optional(value: Option<String>) -> OptionalText {
    value.map_or(OptionalText::None, OptionalText::Some)
}

/// The value of an optional an application supplied.
pub fn optional_value(text: OptionalText) -> Option<String> {
    match text {
        OptionalText::None => None,
        OptionalText::Some(value) => Some(value),
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

/// An opaque page token, carried verbatim in a query parameter. Printable and
/// without the two characters JSON escapes, so a journaled token is its size.
pub fn page_token(value: &str) -> bool {
    (1..=MAX_PAGE_TOKEN_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
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

/// `NotShared`: the calendar exists for the reader, but not through an
/// explicit `writer` or `owner` rule for the reader itself. `NotFound`: the
/// reader cannot see a calendar with that ID at all.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum CalendarOutcome {
    Found(Calendar),
    NotShared,
    NotFound,
}

/// An event's start and end, RFC 3339 with an offset, as Google reports them.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Times {
    pub start: String,
    pub end: String,
}

/// The status together with the times it implies: only a cancelled event may
/// lack them, since Google may report a cancelled exception of a recurring
/// series by its `originalStartTime` alone. Flat rather than a nested
/// `Cancelled([Timed(Times), Untimed])`: the pinned Roc compiler cannot derive
/// a decoder for a union that carries `Times` both directly and nested.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum EventStatus {
    Confirmed(Times),
    Tentative(Times),
    Cancelled(Times),
    CancelledUntimed,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Visibility {
    Default,
    Public,
    Private,
    Confidential,
}

/// A timed event as an application receives it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub status: EventStatus,
    pub visibility: Visibility,
    pub original_start: OptionalText,
    pub organizer: OptionalText,
    pub creator: OptionalText,
    pub meeting_code: OptionalText,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EventsPage {
    pub events: Vec<Event>,
    pub next_page_token: OptionalText,
    /// All-day events on this page, which carry no time and are omitted.
    pub all_day_omitted: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum EventsOutcome {
    Found(EventsPage),
    NotShared,
    NotFound,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum EventOutcome {
    Found(Event),
    /// The event exists but is all-day, so it has no time to report. A
    /// cancelled instance of an all-day series is all-day too.
    AllDay,
    NotShared,
    NotFound,
}

/// Whether the reader's own ACL rule, read by its id `user:{reader}`, holds
/// `writer` or `owner`. A lesser role is not shared. The rule must be the one
/// asked for: any other scope is a response the adapter cannot trust, so a
/// group, domain or default rule never counts, however much it grants.
pub fn parse_reader_rule(body: &[u8], reader: &str) -> Result<bool, Failure> {
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
    let rule: Rule = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    let role = GroupRole::from_google(&rule.role)?;
    let asked = rule.scope.kind == "user"
        && rule
            .scope
            .value
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(reader));
    if !asked {
        return Err(Failure::ResponseInvalid);
    }
    Ok(matches!(role, GroupRole::Writer | GroupRole::Owner))
}

/// Classify a `403` by Google's error reasons, from either error envelope:
/// Calendar's and the Directory's `error.errors[].reason`, or the
/// `error.details[].reason` of an `ErrorInfo` with `error.status` that Meet and
/// other newer APIs send. A rate or quota reason is `RateLimited`; any other
/// reason, or a status with no reason, is `Denied`; a body with neither is
/// `ResponseInvalid`. No reason or status ever leaves this function.
pub fn forbidden(body: &[u8]) -> Failure {
    #[derive(Deserialize)]
    struct Reason {
        reason: String,
    }
    #[derive(Deserialize)]
    struct Detail {
        #[serde(default)]
        errors: Vec<Reason>,
        #[serde(default)]
        details: Vec<serde_json::Value>,
        status: Option<String>,
    }
    #[derive(Deserialize)]
    struct Envelope {
        error: Detail,
    }
    let Ok(envelope) = crate::json::decode::<Envelope>(body) else {
        return Failure::ResponseInvalid;
    };
    let mut reasons = envelope
        .error
        .errors
        .iter()
        .map(|error| error.reason.as_str())
        .chain(
            envelope
                .error
                .details
                .iter()
                .filter_map(|detail| detail.get("reason")?.as_str()),
        )
        .peekable();
    if reasons.peek().is_none() && envelope.error.status.is_none() {
        return Failure::ResponseInvalid;
    }
    if reasons.any(|reason| RATE_REASONS.contains(&reason)) {
        Failure::RateLimited
    } else {
        Failure::Denied
    }
}

/// The calendar's summary. The id must be the calendar that was asked for.
pub fn parse_calendar(body: &[u8], expected: &str) -> Result<String, Failure> {
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
    Ok(calendar.summary)
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
struct SolutionKeyDto {
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
struct SolutionDto {
    key: Option<SolutionKeyDto>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConferenceDto {
    conference_id: Option<String>,
    conference_solution: Option<SolutionDto>,
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

/// An address as reported, from an email character set with nothing JSON
/// escapes: letters, digits, `.` `_` `%` `+` `-` `'` and one `@`. Bounded this
/// way, an event's journaled size is its byte size plus its own quotes.
fn email(value: &str) -> bool {
    (3..=MAX_ADDRESS_BYTES).contains(&value.len())
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.is_empty()
                && !domain.contains('@')
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._%+-'@".contains(&byte))
        })
}

fn address(person: Option<PersonDto>) -> Result<OptionalText, Failure> {
    match person.and_then(|person| person.email) {
        None => Ok(OptionalText::None),
        Some(value) if email(&value) => Ok(OptionalText::Some(value)),
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

/// The Meet code: `conferenceData.conferenceId` when its conference solution is
/// Google Meet, else the path of a `https://meet.google.com/{code}` link; in
/// Meet's shape either way.
fn meet_code(conference: Option<ConferenceDto>, link: Option<&str>) -> Option<String> {
    conference
        .filter(|conference| {
            conference
                .conference_solution
                .as_ref()
                .and_then(|solution| solution.key.as_ref())
                .and_then(|key| key.kind.as_deref())
                == Some("hangoutsMeet")
        })
        .and_then(|conference| conference.conference_id)
        .filter(|code| meeting_code(code))
        .or_else(|| link.and_then(hangout_code))
}

fn event(dto: EventDto) -> Result<Parsed, Failure> {
    if !event_id(&dto.id) {
        return Err(Failure::ResponseInvalid);
    }
    let visibility = match dto.visibility.as_deref() {
        None | Some("default") => Visibility::Default,
        Some("public") => Visibility::Public,
        Some("private") => Visibility::Private,
        Some("confidential") => Visibility::Confidential,
        Some(_) => return Err(Failure::ResponseInvalid),
    };
    // All-day: a date start, or, for a cancelled exception reported without
    // times, a date original start. Either way there is no time to report.
    if all_day(&dto.start) || (dto.start.is_none() && all_day(&dto.original_start_time)) {
        return match dto.status.as_deref() {
            Some("confirmed" | "tentative" | "cancelled") => Ok(Parsed::AllDay),
            _ => Err(Failure::ResponseInvalid),
        };
    }
    let times = match (timed(dto.start)?, timed(dto.end)?) {
        (Some(start), Some(end)) if rfc3339_seconds(&start) <= rfc3339_seconds(&end) => {
            Some(Times { start, end })
        }
        (None, None) => None,
        _ => return Err(Failure::ResponseInvalid),
    };
    let status = match (dto.status.as_deref(), times) {
        (Some("confirmed"), Some(times)) => EventStatus::Confirmed(times),
        (Some("tentative"), Some(times)) => EventStatus::Tentative(times),
        (Some("cancelled"), Some(times)) => EventStatus::Cancelled(times),
        (Some("cancelled"), None) => EventStatus::CancelledUntimed,
        _ => return Err(Failure::ResponseInvalid),
    };
    let original_start = if all_day(&dto.original_start_time) {
        None
    } else {
        timed(dto.original_start_time)?
    };
    Ok(Parsed::Timed(Event {
        id: dto.id,
        status,
        visibility,
        original_start: optional(original_start),
        organizer: address(dto.organizer)?,
        creator: address(dto.creator)?,
        meeting_code: optional(meet_code(dto.conference_data, dto.hangout_link.as_deref())),
    }))
}

/// One events page. A page larger than the requested size or an invalid
/// continuation is refused rather than truncated. Every field is bounded, so a
/// full page always journals within one observation; the size is still
/// checked, never assumed.
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
        next_page_token: optional(page.next_page_token),
        all_day_omitted,
    };
    let encoded = crate::google_workspace::encode(&EventsOutcome::Found(page.clone()));
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
