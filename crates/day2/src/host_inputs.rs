//! Native operator/runtime inputs. These ports are not part of the app SDK.
use anyhow::Result;
use std::{future::Future, pin::Pin, time::Duration};

pub trait Entropy: Send + Sync {
    fn fill(&self, bytes: &mut [u8]) -> Result<()>;
}

pub struct SecureEntropy;

impl Entropy for SecureEntropy {
    fn fill(&self, bytes: &mut [u8]) -> Result<()> {
        getrandom::fill(bytes).map_err(|_| anyhow::anyhow!("entropy_unavailable"))
    }
}

pub(crate) trait Clock: Send + Sync {
    fn wall_time(&self) -> Result<Duration>;

    fn monotonic(&self) -> Duration;
}

pub(crate) struct SystemClock(std::time::Instant);

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self(std::time::Instant::now())
    }
}

impl Clock for SystemClock {
    fn wall_time(&self) -> Result<Duration> {
        Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?)
    }

    fn monotonic(&self) -> Duration {
        self.0.elapsed()
    }
}

pub(crate) trait TickStream: Send {
    fn next(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

pub(crate) trait LiveTicks: Send + Sync {
    fn start(&self, period: Duration) -> Box<dyn TickStream>;
}

pub(crate) struct TokioTicks;

struct TokioTickStream(tokio::time::Interval);

impl LiveTicks for TokioTicks {
    fn start(&self, period: Duration) -> Box<dyn TickStream> {
        let mut interval = tokio::time::interval(period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Box::new(TokioTickStream(interval))
    }
}

impl TickStream for TokioTickStream {
    fn next(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            self.0.tick().await;
        })
    }
}

#[cfg(test)]
pub(crate) mod simulation {
    use super::*;
    use std::sync::Mutex;

    pub(crate) struct SeededEntropy(Mutex<u64>);

    impl SeededEntropy {
        pub(crate) fn new(seed: u64) -> Self {
            Self(Mutex::new(seed))
        }
    }

    impl Entropy for SeededEntropy {
        fn fill(&self, bytes: &mut [u8]) -> Result<()> {
            let mut state = self.0.lock().unwrap();
            for byte in bytes {
                *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                *byte = (*state >> 32) as u8;
            }
            Ok(())
        }
    }

    pub(crate) struct VirtualClock(pub(crate) Mutex<(Duration, Duration)>);

    impl Clock for VirtualClock {
        fn wall_time(&self) -> Result<Duration> {
            Ok(self.0.lock().unwrap().0)
        }

        fn monotonic(&self) -> Duration {
            self.0.lock().unwrap().1
        }
    }
}
