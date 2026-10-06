use anyhow::Result;
use std::path::Path;

pub fn export_file(artifact_directory: &Path, output: Option<&Path>) -> Result<()> {
    day2::app_contracts::export_file(artifact_directory, output)
}
