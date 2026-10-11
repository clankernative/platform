//! Typed assembly outcomes separate provider behavior from capture/admission.
use super::*;
use std::{path::Path, time::Duration};

#[derive(Clone, Debug)]
pub(super) enum AssemblyFailure {
    Unavailable(String),
    Timeout,
    InvalidResponse(String),
    ProviderRejected(String),
}

impl std::fmt::Display for AssemblyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "UI provider unavailable: {message}"),
            Self::Timeout => f.write_str("UI provider timeout"),
            Self::InvalidResponse(message) => write!(f, "invalid UI provider response: {message}"),
            Self::ProviderRejected(message) => {
                write!(f, "UI provider rejected assembly: {message}")
            }
        }
    }
}
impl std::error::Error for AssemblyFailure {}

pub(super) trait UiAssembler {
    fn assemble(&self, request: &AssemblyRequest)
    -> std::result::Result<Envelope, AssemblyFailure>;
}

/// The process adapter implements the port; it never decides admission policy.
pub(super) struct ProcessAssembler<'a> {
    pub executable: &'a Path,
    pub timeout: Duration,
}

fn response(bytes: &[u8]) -> std::result::Result<Envelope, AssemblyFailure> {
    if bytes.len() > MAX_STDOUT {
        return Err(AssemblyFailure::InvalidResponse(
            "output budget exceeded".into(),
        ));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WireEnvelope {
        schema_version: u32,
        ok: bool,
        command: String,
        data: Option<Bundle>,
        diagnostics: Vec<serde_json::Value>,
    }
    let envelope: WireEnvelope = serde_json::from_slice(bytes)
        .map_err(|error| AssemblyFailure::InvalidResponse(error.to_string()))?;
    if envelope.schema_version != 1 || envelope.command != "assemble" {
        return Err(AssemblyFailure::InvalidResponse("protocol mismatch".into()));
    }
    if !envelope.ok || !envelope.diagnostics.is_empty() {
        return Err(AssemblyFailure::ProviderRejected(adapter_failure(
            bytes,
            &[],
        )));
    }
    Ok(Envelope {
        schema_version: envelope.schema_version,
        ok: envelope.ok,
        command: envelope.command,
        data: envelope.data.ok_or_else(|| {
            AssemblyFailure::InvalidResponse("successful response has no bundle".into())
        })?,
        diagnostics: envelope.diagnostics,
    })
}

impl UiAssembler for ProcessAssembler<'_> {
    fn assemble(
        &self,
        request: &AssemblyRequest,
    ) -> std::result::Result<Envelope, AssemblyFailure> {
        let directory = self
            .executable
            .parent()
            .ok_or_else(|| AssemblyFailure::Unavailable("executable parent".into()))?;
        let mut file = tempfile::NamedTempFile::new_in(directory)
            .map_err(|error| AssemblyFailure::Unavailable(error.to_string()))?;
        use std::io::Write;
        let bytes = serde_json::to_vec(request)
            .map_err(|error| AssemblyFailure::InvalidResponse(error.to_string()))?;
        file.write_all(&bytes)
            .map_err(|error| AssemblyFailure::Unavailable(error.to_string()))?;
        let bytes = run_adapter_with_timeout(
            self.executable,
            file.path(),
            Path::new(&request.ui),
            self.timeout,
        )
        .map_err(|error| {
            error
                .downcast_ref::<AssemblyFailure>()
                .cloned()
                .unwrap_or_else(|| AssemblyFailure::Unavailable(format!("{error:#}")))
        })?;
        response(&bytes)
    }
}

/// Deterministic protocol simulator. A caller supplies recorded bytes; there is
/// no component renderer and no filesystem/process behavior in this adapter.
#[cfg(test)]
pub(super) struct SimulatedAssembler {
    pub expected_request: AssemblyRequest,
    pub recorded_response: Vec<u8>,
}

#[cfg(test)]
impl UiAssembler for SimulatedAssembler {
    fn assemble(
        &self,
        request: &AssemblyRequest,
    ) -> std::result::Result<Envelope, AssemblyFailure> {
        let expected =
            serde_json::to_value(&self.expected_request).expect("request is serializable");
        if serde_json::to_value(request).expect("request is serializable") != expected {
            return Err(AssemblyFailure::InvalidResponse(
                "simulator request mismatch".into(),
            ));
        }
        response(&self.recorded_response)
    }
}
