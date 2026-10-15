//! Actual kernel connection-peer observations only. Connection-time credentials
//! and a live pidfd do not identify a message sender, authenticate an endpoint,
//! or qualify a Pod, image, namespace, role, provider or storage authority.
//! No runtime/storage authority factory is supplied here.

use super::native_clock::NativeAcquisition;
use anyhow::{Result, ensure};
use day2_capabilities::Digest;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, Visitor, value::MapAccessDeserializer},
};
use std::{fmt, fs::File, marker::PhantomData, num::NonZeroU32, rc::Rc, thread::ThreadId};

/// Numeric visibility in the receiver's PID namespace, not process authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "visibility", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PeerProcessData {
    Visible { process: NonZeroU32 },
    NotVisible {},
}

impl<'de> Deserialize<'de> for PeerProcessData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "visibility", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Visible { process: NonZeroU32 },
            NotVisible {},
        }
        struct MapOnly;
        impl<'de> Visitor<'de> for MapOnly {
            type Value = PeerProcessData;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a connection-peer PID visibility map")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                Ok(match Wire::deserialize(MapAccessDeserializer::new(map))? {
                    Wire::Visible { process } => PeerProcessData::Visible { process },
                    Wire::NotVisible {} => PeerProcessData::NotVisible {},
                })
            }
        }
        deserializer.deserialize_map(MapOnly)
    }
}

/// Historical connection-creator DATA, never current credentials or permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectionPeerData {
    pub process: PeerProcessData,
    pub user: u32,
    pub group: u32,
}

impl<'de> Deserialize<'de> for ConnectionPeerData {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            process: PeerProcessData,
            user: u32,
            group: u32,
        }
        struct MapOnly;
        impl<'de> Visitor<'de> for MapOnly {
            type Value = ConnectionPeerData;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a connection-peer data map")
            }

            fn visit_map<M: MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Self::Value, M::Error> {
                let wire = Wire::deserialize(MapAccessDeserializer::new(map))?;
                Ok(ConnectionPeerData {
                    process: wire.process,
                    user: wire.user,
                    group: wire.group,
                })
            }
        }
        deserializer.deserialize_map(MapOnly)
    }
}

pub(crate) struct NativeConnectionPeerObservation {
    peer: ConnectionPeerData,
    domain: Digest,
    process: u32,
    thread: ThreadId,
    #[cfg(target_os = "linux")]
    socket: File,
    #[cfg(target_os = "linux")]
    pidfd: File,
    refused: bool,
    local: PhantomData<Rc<()>>,
}

impl NativeConnectionPeerObservation {
    /// Consumes an actual socket descriptor; no caller PID/UID/claim/path is
    /// accepted. This leaf cannot prove when the caller opened the connection.
    /// A future qualified transport must itself connect under the SAME original
    /// acquisition before using this observation. No such transport is added.
    pub(super) fn observe(socket: File, acquisition: &mut NativeAcquisition) -> Result<Self> {
        let _ = &socket;
        let result = (|| {
            #[cfg(target_os = "linux")]
            {
                let domain = acquisition.sample()?.domain;
                let process = std::process::id();
                let thread = std::thread::current().id();
                let peer = credentials(&socket, acquisition)?;
                acquisition.remaining()?;
                let pidfd = File::from(nix::sys::socket::getsockopt(
                    &socket,
                    nix::sys::socket::sockopt::PeerPidfd,
                )?);
                acquisition.remaining()?;
                live_pidfd(&pidfd, acquisition)?;
                let mut observed = Self {
                    peer,
                    domain,
                    process,
                    thread,
                    socket,
                    pidfd,
                    refused: false,
                    local: PhantomData,
                };
                observed.check(acquisition)?;
                Ok(observed)
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_connection_peer_platform_unsupported")
        })();
        if result.is_err() {
            acquisition.refuse();
        }
        result
    }

    /// Checks the retained original pidfd, rather than reopening a numeric PID.
    /// Socket credentials are still cached connection-time DATA, not current
    /// effective credentials or per-message sender attribution.
    pub(super) fn check(&mut self, acquisition: &mut NativeAcquisition) -> Result<()> {
        let result = (|| {
            ensure!(!self.refused, "native_connection_peer_refused");
            ensure!(
                std::process::id() == self.process && std::thread::current().id() == self.thread,
                "native_connection_peer_owner_changed"
            );
            ensure!(
                acquisition.sample()?.domain == self.domain,
                "native_connection_peer_acquisition_changed"
            );
            #[cfg(target_os = "linux")]
            {
                live_pidfd(&self.pidfd, acquisition)?;
                ensure!(
                    credentials(&self.socket, acquisition)? == self.peer,
                    "native_connection_peer_changed"
                );
                live_pidfd(&self.pidfd, acquisition)?;
                acquisition.remaining()?;
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            anyhow::bail!("native_connection_peer_platform_unsupported")
        })();
        if result.is_err() {
            self.refused = true;
            acquisition.refuse();
        }
        result
    }

    /// Discards socket/pidfd ownership. Serialized DATA cannot recreate them.
    pub(super) fn into_data(self) -> ConnectionPeerData {
        self.peer
    }
}

#[cfg(target_os = "linux")]
fn credentials(socket: &File, acquisition: &mut NativeAcquisition) -> Result<ConnectionPeerData> {
    acquisition.remaining()?;
    let kind = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::SockType)?;
    acquisition.remaining()?;
    ensure!(
        matches!(
            kind,
            nix::sys::socket::SockType::Stream | nix::sys::socket::SockType::SeqPacket
        ),
        "native_connection_peer_socket_type"
    );
    acquisition.remaining()?;
    let peer = nix::sys::socket::getsockopt(socket, nix::sys::socket::sockopt::PeerCredentials)?;
    acquisition.remaining()?;
    ensure!(
        peer.uid() != u32::MAX && peer.gid() != u32::MAX,
        "native_connection_peer_credentials_unavailable"
    );
    Ok(ConnectionPeerData {
        process: process_visibility(peer.pid())?,
        user: peer.uid(),
        group: peer.gid(),
    })
}

fn process_visibility(process: i32) -> Result<PeerProcessData> {
    ensure!(
        process >= 0,
        "native_connection_peer_credentials_unavailable"
    );
    Ok(match NonZeroU32::new(process.try_into()?) {
        Some(process) => PeerProcessData::Visible { process },
        None => PeerProcessData::NotVisible {},
    })
}

#[cfg(target_os = "linux")]
fn live_pidfd(pidfd: &File, acquisition: &mut NativeAcquisition) -> Result<()> {
    use std::os::fd::AsFd;
    acquisition.remaining()?;
    let mut descriptors = [nix::poll::PollFd::new(
        pidfd.as_fd(),
        nix::poll::PollFlags::POLLIN,
    )];
    let ready = nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::ZERO)?;
    acquisition.remaining()?;
    ensure!(
        ready == 0
            && descriptors[0]
                .revents()
                .is_some_and(|flags| flags.is_empty()),
        "native_connection_peer_exited_or_unknown"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
