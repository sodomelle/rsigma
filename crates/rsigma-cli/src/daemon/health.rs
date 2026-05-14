use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct HealthState {
    pub ready: Arc<AtomicBool>,
}

impl HealthState {
    pub fn new() -> Self {
        HealthState {
            ready: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        let previous = self.ready.swap(ready, Ordering::AcqRel);
        if previous != ready {
            tracing::info!(ready, "Readiness state changed");
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_ready_records_transition_correctly() {
        let state = HealthState::new();
        assert!(!state.is_ready());
        state.set_ready(true);
        assert!(state.is_ready());
        // No-op transition: still ready, no panic, no flip.
        state.set_ready(true);
        assert!(state.is_ready());
        state.set_ready(false);
        assert!(!state.is_ready());
    }
}
