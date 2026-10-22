//! Bounded, untrusted wakeup DATA on an already retained peer socket. These
//! fields supply neither a signer/role nor file, epoch, writer or consumer proof.

use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{Deserialize, Serialize};

pub(super) const MAX_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PeerChannel {
    Storage,
    Serving,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct IdleRequest {
    channel: PeerChannel,
    initial: Digest,
    sequence: u64,
}

impl IdleRequest {
    pub(super) fn encode(channel: PeerChannel, initial: &Digest, sequence: u64) -> Result<Vec<u8>> {
        ensure!(sequence > 0, "native_peer_idle_sequence");
        let bytes = serde_json::to_vec(&Self {
            channel,
            initial: initial.clone(),
            sequence,
        })?;
        ensure!(bytes.len() <= MAX_BYTES, "native_peer_idle_packet_bound");
        Ok(bytes)
    }

    pub(super) fn require(
        bytes: &[u8],
        channel: PeerChannel,
        initial: &Digest,
        sequence: u64,
    ) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_BYTES,
            "native_peer_idle_packet_bound"
        );
        let value: serde_json::Value = crate::json::decode(bytes)?;
        ensure!(value.is_object(), "native_peer_idle_record_object_required");
        let value: Self = serde_json::from_value(value)?;
        ensure!(
            sequence > 0
                && value.channel == channel
                && value.initial == *initial
                && value.sequence == sequence,
            "native_peer_idle_request_changed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_data_is_bound_to_its_channel_original_and_next_sequence() {
        let initial = Digest::new(b"retained peer");
        for channel in [PeerChannel::Storage, PeerChannel::Serving] {
            let bytes = IdleRequest::encode(channel, &initial, u64::MAX).unwrap();
            IdleRequest::require(&bytes, channel, &initial, u64::MAX).unwrap();
            for other in [PeerChannel::Storage, PeerChannel::Serving] {
                if other != channel {
                    assert!(IdleRequest::require(&bytes, other, &initial, u64::MAX).is_err());
                }
            }
            assert!(
                IdleRequest::require(&bytes, channel, &Digest::new(b"foreign"), u64::MAX).is_err()
            );
            assert!(IdleRequest::require(&bytes, channel, &initial, 1).is_err());
            assert!(IdleRequest::require(&bytes, channel, &initial, 0).is_err());
        }
        assert!(IdleRequest::encode(PeerChannel::Storage, &initial, 0).is_err());
    }

    #[test]
    fn idle_data_refuses_duplicate_unknown_missing_array_and_unbounded_records() {
        let initial = Digest::new(b"retained peer");
        let bytes = IdleRequest::encode(PeerChannel::Storage, &initial, 1).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["channel", "initial", "sequence"] {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(
                IdleRequest::require(
                    &serde_json::to_vec(&changed).unwrap(),
                    PeerChannel::Storage,
                    &initial,
                    1
                )
                .is_err()
            );
        }
        let mut changed = original;
        changed["role"] = serde_json::json!("epoch_controller");
        assert!(
            IdleRequest::require(
                &serde_json::to_vec(&changed).unwrap(),
                PeerChannel::Storage,
                &initial,
                1
            )
            .is_err()
        );
        let duplicate = String::from_utf8(bytes)
            .unwrap()
            .replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1");
        assert!(
            IdleRequest::require(duplicate.as_bytes(), PeerChannel::Storage, &initial, 1).is_err()
        );
        for bytes in [vec![], b"[]".to_vec(), vec![b' '; MAX_BYTES + 1]] {
            assert!(IdleRequest::require(&bytes, PeerChannel::Storage, &initial, 1).is_err());
        }
    }
}
