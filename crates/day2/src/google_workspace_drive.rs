//! Drive sharing for `GoogleWorkspace`, the provider's only write: the
//! reviewed permission requests, the exact body, and the strict parsing of a
//! file's permissions and of the permission Drive creates. The pipeline in
//! `google_workspace` decides order, identity, bounds and classification.
use crate::google_workspace::Failure;
use crate::google_workspace_calendar as calendar;
use serde::{Deserialize, Serialize};

/// Drive's scope, which permission changes need. Only an event's derived owner
/// is ever delegated to with it, together with Meet's read scope.
pub const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive";
/// Permissions requested per page (Drive's maximum), and pages read.
pub const PERMISSION_PAGE_SIZE: u32 = 100;
pub const PERMISSION_PAGE_CEILING: u64 = 2;
pub const PERMISSIONS_FIELDS: &str = "permissions(id,type,role,emailAddress,deleted),nextPageToken";
pub const CREATED_FIELDS: &str = "id,type,role,emailAddress";
const MAX_PERMISSION_ID_BYTES: usize = 128;
/// Drive's roles from the least to the most: every one of them lets a group
/// read the file.
const ROLES: [&str; 6] = [
    "reader",
    "commenter",
    "writer",
    "fileOrganizer",
    "organizer",
    "owner",
];

/// A permission on the shared file.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Permission {
    pub permission_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub enum ShareOutcome {
    /// The group was given `reader` now.
    Shared(Permission),
    /// The group already held `reader` or more; nothing was created.
    AlreadyShared(Permission),
    /// The artifact exists but Meet has not generated its file yet.
    NotReady,
    /// Drive refused the sharing request itself (`invalidSharingRequest`): an
    /// unknown group, or a change the organization's sharing policy forbids.
    SharingRefused,
    /// The event's records are in more than one space.
    Conflict,
    NoOwner,
    NoMeeting,
    AllDay,
    NotShared,
    /// No such event, artifact of this event, or file the owner can see.
    NotFound,
}

/// The one permission ever created: the group as `reader`, nothing else.
pub fn share_body(group: &str) -> String {
    format!(
        r#"{{"type":"group","role":"reader","emailAddress":{}}}"#,
        serde_json::Value::from(group)
    )
}

fn permission_id(value: &str) -> bool {
    (1..=MAX_PERMISSION_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionDto {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    role: String,
    email_address: Option<String>,
    #[serde(default)]
    deleted: bool,
}

/// Whether a permission is a live grant to exactly this group. Addresses are
/// compared ignoring ASCII case, as Google treats them and as the ACL read
/// does; the group asked about is an exact lowercase address.
fn grants(permission: &PermissionDto, group: &str) -> Result<bool, Failure> {
    if !permission_id(&permission.id) || !ROLES.contains(&permission.role.as_str()) {
        return Err(Failure::ResponseInvalid);
    }
    Ok(permission.kind == "group"
        && !permission.deleted
        && permission
            .email_address
            .as_deref()
            .is_some_and(|email| email.eq_ignore_ascii_case(group)))
}

/// One page of a file's permissions: the ID of a live `reader`-or-more grant
/// to the group if this page has one, and the continuation.
pub fn parse_permissions_page(
    body: &[u8],
    group: &str,
) -> Result<(Option<String>, Option<String>), Failure> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Page {
        #[serde(default)]
        permissions: Vec<PermissionDto>,
        next_page_token: Option<String>,
    }
    let page: Page = crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if page.permissions.len() > PERMISSION_PAGE_SIZE as usize
        || page
            .next_page_token
            .as_deref()
            .is_some_and(|token| !calendar::page_token(token))
    {
        return Err(Failure::ResponseInvalid);
    }
    for permission in page.permissions {
        if grants(&permission, group)? {
            return Ok((Some(permission.id), None));
        }
    }
    Ok((None, page.next_page_token))
}

/// The permission Drive created, which must echo exactly what was asked: a
/// group, `reader`, this group's address.
pub fn parse_created(body: &[u8], group: &str) -> Result<String, Failure> {
    let permission: PermissionDto =
        crate::json::decode(body).map_err(|_| Failure::ResponseInvalid)?;
    if !grants(&permission, group)? || permission.role != "reader" {
        return Err(Failure::ResponseInvalid);
    }
    Ok(permission.id)
}

/// Whether a `400` is Drive refusing the sharing request itself.
pub fn sharing_refused(body: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Reason {
        reason: String,
    }
    #[derive(Deserialize)]
    struct Detail {
        #[serde(default)]
        errors: Vec<Reason>,
    }
    #[derive(Deserialize)]
    struct Envelope {
        error: Detail,
    }
    crate::json::decode::<Envelope>(body).is_ok_and(|envelope| {
        envelope
            .error
            .errors
            .iter()
            .any(|error| error.reason == "invalidSharingRequest")
    })
}
