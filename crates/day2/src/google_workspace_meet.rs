//! Meet reads for `GoogleWorkspace`: who an event's conferences are read as,
//! the reviewed conference-record filter and request constants, and the strict
//! parsing of Meet's conference records and their recordings, smart notes and
//! transcripts into the closed values an application receives. The pipeline in
//! `google_workspace` decides order, identity, bounds and classification.
use crate::carta::OptionalText;
use crate::google_workspace::Failure;
use crate::google_workspace_calendar::{self as calendar, Event, Times};
use day2_capabilities::resources::google_workspace_address;
use serde::{Deserialize, Serialize};

/// The one scope an event's owner is impersonated with.
pub const MEET_READ_SCOPE: &str = "https://www.googleapis.com/auth/meetings.space.readonly";
/// Conference records are searched from this long before the event starts to
/// this long after it ends, as the legacy sharing job searched them.
pub const RECORD_WINDOW_SECONDS: i64 = 30 * 60;
/// Conference records an event may have: the first call and its rejoins.
pub const MAX_RECORDS: usize = 5;
/// Records requested per page, and pages read; a short page may continue.
pub const RECORD_PAGE_SIZE: u32 = 5;
pub const RECORD_PAGE_CEILING: u64 = 2;
/// Recordings, smart notes or transcripts one conference record may have, of
/// each kind. One page of them is read.
pub const MAX_ARTIFACTS: usize = 5;
pub const ARTIFACT_PAGE_SIZE: u32 = 5;
pub const ARTIFACT_PAGE_CEILING: u64 = 1;
/// A Meet resource ID: a conference record, space or artifact.
pub(crate) const MAX_MEET_ID_BYTES: usize = 128;
/// A Drive file or Docs document ID.
pub(crate) const MAX_FILE_ID_BYTES: usize = 128;
pub const RECORDS_FIELDS: &str = "conferenceRecords(name,space,startTime,endTime),nextPageToken";

/// The three artifact collections of a conference record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Collection {
    Recordings,
    SmartNotes,
    Transcripts,
}

impl Collection {
    pub const ALL: [Self; 3] = [Self::Recordings, Self::SmartNotes, Self::Transcripts];

    /// The path segment, which is also the list's key in the response.
    pub fn segment(self) -> &'static str {
        match self {
            Self::Recordings => "recordings",
            Self::SmartNotes => "smartNotes",
            Self::Transcripts => "transcripts",
        }
    }

    /// The reviewed fields mask.
    pub fn fields(self) -> &'static str {
        match self {
            Self::Recordings => "recordings(name,state,driveDestination(file)),nextPageToken",
            Self::SmartNotes => "smartNotes(name,state,docsDestination(document)),nextPageToken",
            Self::Transcripts => "transcripts(name,state,docsDestination(document)),nextPageToken",
        }
    }

    /// The reviewed fields mask for one artifact of this kind.
    pub fn artifact_fields(self) -> &'static str {
        match self {
            Self::Recordings => "name,state,driveDestination(file)",
            Self::SmartNotes | Self::Transcripts => "name,state,docsDestination(document)",
        }
    }

    /// The request's name for timing.
    pub fn endpoint(self) -> &'static str {
        match self {
            Self::Recordings => "meet_recordings",
            Self::SmartNotes => "meet_smart_notes",
            Self::Transcripts => "meet_transcripts",
        }
    }
}

/// Where an artifact is in Meet's progression. `STATE_UNSPECIFIED` is never
/// used, so it is refused.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum ArtifactState {
    Started,
    Ended,
    FileGenerated,
}

/// A recording and the Drive file it was saved to. Meet's reference does not
/// say the file is set only once `FileGenerated`, so it is optional at every
/// state.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Recording {
    pub name: String,
    pub state: ArtifactState,
    pub file_id: OptionalText,
}

/// A smart note or transcript and the Docs document it was saved to.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Document {
    pub name: String,
    pub state: ArtifactState,
    pub document_id: OptionalText,
}

/// One conference: a call in the event's space, of which a rejoin is another.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ConferenceRecord {
    pub name: String,
    pub space: String,
    pub start_time: String,
    /// Unset while the conference is ongoing.
    pub end_time: OptionalText,
    pub recordings: Vec<Recording>,
    pub smart_notes: Vec<Document>,
    pub transcripts: Vec<Document>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EventConferences {
    /// The person the conferences were read as.
    pub owner: String,
    pub meeting_code: String,
    /// In Meet's order: the latest start first.
    pub records: Vec<ConferenceRecord>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum EventConferencesOutcome {
    Found(EventConferences),
    /// Neither the organizer nor, for a group or resource calendar, the
    /// creator is a person in the grant's email domain.
    NoOwner,
    /// The event has no Meet code.
    NoMeeting,
    /// The records for the code and window are in more than one space.
    Conflict,
    AllDay,
    NotShared,
    NotFound,
}

fn text(value: &OptionalText) -> Option<&str> {
    match value {
        OptionalText::Some(value) => Some(value),
        OptionalText::None => None,
    }
}

/// The person an event's conferences are read as: always its creator, which
/// Google sets and nobody can write, and only when the creator is a person in
/// `email_domain` and either is the organizer too, or the organizer is a
/// group or resource calendar.
///
/// The organizer alone is never trusted: Google lets `events.import` set any
/// organizer, so a writer on a calendar in play could name anyone in the
/// domain. A person in `email_domain` is an exact Workspace address
/// (`google_workspace_address`, the rule `calendar_reader` follows) whose
/// domain is exactly `email_domain`. Everyone else, including an assistant
/// who created an event for someone else, is no owner: this fails closed.
pub fn owner(event: &Event, email_domain: &str) -> Option<String> {
    let organizer = text(&event.organizer)?;
    let creator = text(&event.creator)?;
    let person = google_workspace_address(creator).is_ok_and(|(_, domain)| domain == email_domain);
    let calendar = organizer.ends_with("@group.calendar.google.com")
        || organizer.ends_with("@resource.calendar.google.com");
    (person && (organizer == creator || calendar)).then(|| creator.to_owned())
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_prime = (5 * doy + 2) / 153;
    let day = doy - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the epoch, within years 0–9999.
pub fn utc(seconds: i64) -> Option<String> {
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let (year, month, day) = civil_from_days(days);
    (0..=9_999).contains(&year).then(|| {
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            rest / 3_600,
            rest % 3_600 / 60,
            rest % 60
        )
    })
}

/// The window conference records may start in: the event's span widened by
/// thirty minutes on each side, in whole seconds.
pub fn record_window(times: &Times) -> Option<(i64, i64)> {
    let start = calendar::rfc3339_seconds(&times.start)?;
    let end = calendar::rfc3339_seconds(&times.end)?;
    Some((
        start.checked_sub(RECORD_WINDOW_SECONDS)?,
        end.checked_add(RECORD_WINDOW_SECONDS)?,
    ))
}

/// The reviewed filter, exactly: the meeting code and the start-time window.
pub fn record_filter(code: &str, (from, to): (i64, i64)) -> Option<String> {
    Some(format!(
        r#"space.meeting_code = "{code}" AND start_time >= "{}" AND start_time <= "{}""#,
        utc(from)?,
        utc(to)?
    ))
}

/// Seconds since the epoch of a Meet timestamp as protobuf's JSON mapping
/// writes it: UTC with `Z` and 0, 3, 6 or 9 fractional digits. The fraction is
/// dropped, so a window check on it is never stricter than Meet's own.
pub fn meet_timestamp(value: &str) -> Option<i64> {
    let body = value.strip_suffix('Z')?;
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    if whole.len() != 19
        || ![0, 3, 6, 9].contains(&fraction.len())
        || (body.contains('.') && fraction.is_empty())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    calendar::rfc3339_seconds(&format!("{whole}Z"))
}

fn meet_id(value: &str) -> bool {
    (1..=MAX_MEET_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// The ID of `conferenceRecords/{id}`, which later requests put in their path.
pub fn record_id(name: &str) -> Option<&str> {
    name.strip_prefix("conferenceRecords/")
        .filter(|id| meet_id(id))
}

/// `spaces/{id}`.
pub fn space_name(name: &str) -> bool {
    name.strip_prefix("spaces/").is_some_and(meet_id)
}

/// The record, collection and ID of an exact artifact name,
/// `conferenceRecords/{record}/{collection}/{id}`.
pub fn parse_artifact_name(name: &str) -> Option<(&str, Collection, &str)> {
    let mut parts = name.split('/');
    let (Some("conferenceRecords"), Some(record), Some(segment), Some(id), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let collection = Collection::ALL
        .into_iter()
        .find(|collection| collection.segment() == segment)?;
    (meet_id(record) && meet_id(id)).then_some((record, collection, id))
}

/// `conferenceRecords/{record}/{collection}/{id}` for exactly this record.
pub fn artifact_name(name: &str, record: &str, collection: Collection) -> bool {
    name.strip_prefix("conferenceRecords/")
        .and_then(|rest| rest.strip_prefix(record))
        .and_then(|rest| rest.strip_prefix('/'))
        .and_then(|rest| rest.strip_prefix(collection.segment()))
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(meet_id)
}

/// A bare Drive file or Docs document ID, as the reference gives one.
fn file_id(value: &str) -> bool {
    (1..=MAX_FILE_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// One page of a Meet list: its items and the continuation, if any.
pub type Page<T> = (Vec<T>, Option<String>);

/// A listed conference record and its ID, which the requests that follow put
/// in their path.
pub type Listed = (String, ConferenceRecord);

fn optional(value: Option<String>) -> OptionalText {
    value.map_or(OptionalText::None, OptionalText::Some)
}

/// One page of conference records for a filter, each with its ID for the
/// requests that follow. Each record is validated and must start inside
/// `window`: a record outside it means Google did not apply the filter, so the
/// page is refused rather than filtered.
pub fn parse_records_page(body: &[u8], window: (i64, i64)) -> Result<Page<Listed>, Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RecordDto {
        name: String,
        space: String,
        start_time: String,
        end_time: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        #[serde(default)]
        conference_records: Vec<RecordDto>,
        next_page_token: Option<String>,
    }
    let page: Page = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if page.conference_records.len() > RECORD_PAGE_SIZE as usize
        || page
            .next_page_token
            .as_deref()
            .is_some_and(|token| !calendar::page_token(token))
    {
        return Err(Failure::ResponseInvalid);
    }
    let mut records = Vec::new();
    for record in page.conference_records {
        let start = meet_timestamp(&record.start_time).ok_or(Failure::ResponseInvalid)?;
        let end = match &record.end_time {
            Some(end) => Some(meet_timestamp(end).ok_or(Failure::ResponseInvalid)?),
            None => None,
        };
        let id = record_id(&record.name)
            .ok_or(Failure::ResponseInvalid)?
            .to_owned();
        if !space_name(&record.space)
            || !(window.0..=window.1).contains(&start)
            || end.is_some_and(|end| end < start)
        {
            return Err(Failure::ResponseInvalid);
        }
        records.push((
            id,
            ConferenceRecord {
                name: record.name,
                space: record.space,
                start_time: record.start_time,
                end_time: optional(record.end_time),
                recordings: Vec::new(),
                smart_notes: Vec::new(),
                transcripts: Vec::new(),
            },
        ));
    }
    Ok((records, page.next_page_token))
}

/// One artifact as parsed: its name, state and file or document ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub state: ArtifactState,
    pub id: Option<String>,
}

#[derive(Deserialize)]
struct DriveDto {
    file: Option<String>,
}

#[derive(Deserialize)]
struct DocsDto {
    document: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactDto {
    name: String,
    state: String,
    drive_destination: Option<DriveDto>,
    docs_destination: Option<DocsDto>,
}

/// One artifact as Meet reports it. A recording carries only a Drive
/// destination and a smart note or transcript only a Docs destination.
fn artifact(item: ArtifactDto, record: &str, collection: Collection) -> Result<Artifact, Failure> {
    let state = match item.state.as_str() {
        "STARTED" => ArtifactState::Started,
        "ENDED" => ArtifactState::Ended,
        "FILE_GENERATED" => ArtifactState::FileGenerated,
        _ => return Err(Failure::ResponseInvalid),
    };
    let id = match (collection, item.drive_destination, item.docs_destination) {
        (Collection::Recordings, drive, None) => drive.and_then(|drive| drive.file),
        (Collection::SmartNotes | Collection::Transcripts, None, docs) => {
            docs.and_then(|docs| docs.document)
        }
        _ => return Err(Failure::ResponseInvalid),
    };
    if id.as_deref().is_some_and(|id| !file_id(id))
        || !artifact_name(&item.name, record, collection)
    {
        return Err(Failure::ResponseInvalid);
    }
    Ok(Artifact {
        name: item.name,
        state,
        id,
    })
}

/// One page of one record's artifacts of one kind.
pub fn parse_artifact_page(
    body: &[u8],
    record: &str,
    collection: Collection,
) -> Result<Page<Artifact>, Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        recordings: Option<Vec<ArtifactDto>>,
        smart_notes: Option<Vec<ArtifactDto>>,
        transcripts: Option<Vec<ArtifactDto>>,
        next_page_token: Option<String>,
    }
    let page: Page = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    let (items, others) = match collection {
        Collection::Recordings => (page.recordings, [page.smart_notes, page.transcripts]),
        Collection::SmartNotes => (page.smart_notes, [page.recordings, page.transcripts]),
        Collection::Transcripts => (page.transcripts, [page.recordings, page.smart_notes]),
    };
    let items = items.unwrap_or_default();
    if others.iter().any(Option::is_some)
        || items.len() > ARTIFACT_PAGE_SIZE as usize
        || page
            .next_page_token
            .as_deref()
            .is_some_and(|token| !calendar::page_token(token))
    {
        return Err(Failure::ResponseInvalid);
    }
    let artifacts = items
        .into_iter()
        .map(|item| artifact(item, record, collection))
        .collect::<Result<_, _>>()?;
    Ok((artifacts, page.next_page_token))
}

/// One artifact read by its exact name, which the reply must repeat.
pub fn parse_artifact(body: &[u8], name: &str) -> Result<Artifact, Failure> {
    let (record, collection, _) = parse_artifact_name(name).ok_or(Failure::ResponseInvalid)?;
    let item: ArtifactDto = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if item.name != name {
        return Err(Failure::ResponseInvalid);
    }
    artifact(item, record, collection)
}

/// Put one record's artifacts of one kind in place.
pub fn attach(record: &mut ConferenceRecord, collection: Collection, artifacts: Vec<Artifact>) {
    match collection {
        Collection::Recordings => {
            record.recordings = artifacts
                .into_iter()
                .map(|artifact| Recording {
                    name: artifact.name,
                    state: artifact.state,
                    file_id: optional(artifact.id),
                })
                .collect();
        }
        Collection::SmartNotes | Collection::Transcripts => {
            let documents = artifacts
                .into_iter()
                .map(|artifact| Document {
                    name: artifact.name,
                    state: artifact.state,
                    document_id: optional(artifact.id),
                })
                .collect();
            if collection == Collection::SmartNotes {
                record.smart_notes = documents;
            } else {
                record.transcripts = documents;
            }
        }
    }
}

/// The finished outcome. Every field is bounded to characters JSON never
/// escapes, so the largest admissible outcome journals within one observation
/// (a test proves it). As `parse_events_page` does for an events page, the
/// outcome is still measured, never assumed to fit.
pub fn found(conferences: EventConferences) -> Result<EventConferencesOutcome, Failure> {
    let outcome = EventConferencesOutcome::Found(conferences);
    let encoded = crate::google_workspace::encode(&outcome);
    match crate::capture_delivery::journal_bytes(&encoded) {
        Ok(bytes) if bytes <= crate::capture_delivery::MAX_PAGE_JOURNAL_BYTES => Ok(outcome),
        _ => Err(Failure::ResponseTooLarge),
    }
}
