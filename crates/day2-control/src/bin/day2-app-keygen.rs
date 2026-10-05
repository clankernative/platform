//! One-shot operator key creation. Private bytes go only to a new protected file.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf};

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        arguments.len() == 2,
        "usage: day2-app-keygen KEY_ID NEW_PRIVATE_FILE"
    );
    let id = arguments[0].to_str().context("key id encoding")?;
    let path = PathBuf::from(&arguments[1]);
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("key entropy unavailable"))?;
    let signer = day2::delegation_wire::Signer::from_pkcs8(id, pkcs8.as_ref())?;
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&path)?;
    file.write_all(pkcs8.as_ref())?;
    file.sync_all()?;
    let loaded = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("created key could not be loaded"))?;
    ensure!(
        loaded.public_key().as_ref() == signer.public_key(),
        "created key identity changed"
    );
    println!(
        "{}",
        serde_json::json!({"id":id,"public_key":URL_SAFE_NO_PAD.encode(signer.public_key())})
    );
    Ok(())
}
