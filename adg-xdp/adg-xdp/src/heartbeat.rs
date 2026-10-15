//! Daemon heartbeat: lets the SDN controller tell fresh HOST_TRUST / HOST_RISK telemetry from
//! values frozen by a crashed or restarted daemon. Pinned maps outlive the daemon, so readability
//! alone says nothing about freshness.
//!
//! The heartbeat is a small JSON file replaced atomically (write temp file + rename) after every
//! processing cycle. The format is a cross-language contract with `controller/telemetry.py`;
//! `tests/fixtures/heartbeat_v1.json` is checked by both test suites.

use std::{fs, io::Write, path::Path};

pub const SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_HEARTBEAT_PATH: &str = "/run/adg/heartbeat.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonState {
    /// Maps pinned, no processing cycle completed yet in this incarnation.
    Starting,
    Running,
    /// Clean shutdown; pinned maps keep their last values.
    Stopped,
}

impl DaemonState {
    fn as_str(self) -> &'static str {
        match self {
            DaemonState::Starting => "starting",
            DaemonState::Running => "running",
            DaemonState::Stopped => "stopped",
        }
    }
}

/// Error counts for one processing cycle.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CycleOutcome {
    pub hosts: usize,
    pub stats_read_errors: u64,
    pub trust_write_errors: u64,
    pub risk_write_errors: u64,
    /// FLOW_EVENTS samples the kernel dropped (ring buffer full) since the previous cycle.
    pub flow_events_lost: u64,
    /// FLOW_EVENTS consumer threads still running / started. Risk is computed from the
    /// FlowTable they feed, so a dead consumer silently freezes the risk inputs.
    pub flow_consumers_alive: usize,
    pub flow_consumers_expected: usize,
}

impl CycleOutcome {
    /// Trust telemetry is valid only if every host was read and every HOST_TRUST write succeeded.
    pub fn trust_ok(&self) -> bool {
        self.stats_read_errors == 0 && self.trust_write_errors == 0
    }

    /// Risk additionally requires complete flow-event input: every consumer alive, no lost samples.
    pub fn risk_ok(&self) -> bool {
        self.stats_read_errors == 0
            && self.risk_write_errors == 0
            && self.flow_events_lost == 0
            && self.flow_consumers_alive == self.flow_consumers_expected
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heartbeat {
    /// Unique per daemon run: changes on every restart even if the PID is reused.
    pub incarnation: String,
    pub pid: u32,
    pub state: DaemonState,
    /// Number of completed processing cycles in this incarnation.
    pub generation: u64,
    /// CLOCK_MONOTONIC at the end of the last cycle (same clock as Python `time.monotonic_ns`).
    pub monotonic_ns: u64,
    pub wall_unix_ms: u64,
    /// Kernel IDs of the maps this incarnation writes; a controller holding a different ID is
    /// reading a replaced (orphaned) map.
    pub trust_map_id: u32,
    pub risk_map_id: u32,
    pub last_cycle: CycleOutcome,
}

impl Heartbeat {
    pub fn new(pid: u32, start_monotonic_ns: u64, trust_map_id: u32, risk_map_id: u32) -> Self {
        Heartbeat {
            incarnation: format!("{pid}-{start_monotonic_ns}"),
            pid,
            state: DaemonState::Starting,
            generation: 0,
            monotonic_ns: start_monotonic_ns,
            wall_unix_ms: 0,
            trust_map_id,
            risk_map_id,
            last_cycle: CycleOutcome::default(),
        }
    }

    /// Record a completed cycle. Called only after the whole pipeline (stats read, trust and risk
    /// computation, map writes) has run for every host.
    pub fn complete_cycle(&mut self, outcome: CycleOutcome, monotonic_ns: u64, wall_unix_ms: u64) {
        self.state = DaemonState::Running;
        self.generation += 1;
        self.monotonic_ns = monotonic_ns;
        self.wall_unix_ms = wall_unix_ms;
        self.last_cycle = outcome;
    }

    pub fn stop(&mut self, monotonic_ns: u64, wall_unix_ms: u64) {
        self.state = DaemonState::Stopped;
        self.monotonic_ns = monotonic_ns;
        self.wall_unix_ms = wall_unix_ms;
    }

    pub fn to_json(&self) -> String {
        let c = &self.last_cycle;
        let started = self.state != DaemonState::Starting;
        format!(
            concat!(
                "{{\"schema\":{},\"incarnation\":\"{}\",\"pid\":{},\"state\":\"{}\",",
                "\"generation\":{},\"monotonic_ns\":{},\"wall_unix_ms\":{},",
                "\"trust_map_id\":{},\"risk_map_id\":{},\"hosts\":{},",
                "\"stats_read_errors\":{},\"trust_write_errors\":{},\"risk_write_errors\":{},",
                "\"flow_events_lost\":{},\"flow_consumers_alive\":{},\"flow_consumers_expected\":{},",
                "\"trust_ok\":{},\"risk_ok\":{}}}\n"
            ),
            SCHEMA_VERSION, self.incarnation, self.pid, self.state.as_str(),
            self.generation, self.monotonic_ns, self.wall_unix_ms,
            self.trust_map_id, self.risk_map_id, c.hosts,
            c.stats_read_errors, c.trust_write_errors, c.risk_write_errors,
            c.flow_events_lost, c.flow_consumers_alive, c.flow_consumers_expected,
            started && c.trust_ok(), started && c.risk_ok(),
        )
    }
}

/// Replace `path` atomically so a reader never sees a partial heartbeat.
pub fn write_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_heartbeat() -> Heartbeat {
        let mut hb = Heartbeat::new(4242, 123456789, 101, 102);
        let outcome = CycleOutcome { hosts: 3, flow_consumers_alive: 4, flow_consumers_expected: 4,
                                     ..Default::default() };
        for _ in 0..7 {
            hb.complete_cycle(outcome, 987654321000, 1760000000000);
        }
        hb
    }

    #[test]
    fn test_json_matches_shared_fixture() {
        // Cross-language contract with controller/telemetry.py (tests/test_telemetry.py reads the same file).
        let fixture = include_str!("../../../tests/fixtures/heartbeat_v1.json");
        assert_eq!(fixture_heartbeat().to_json(), fixture);
    }

    #[test]
    fn test_incarnation_changes_across_restarts() {
        let a = Heartbeat::new(4242, 1_000, 1, 2);
        let b = Heartbeat::new(4242, 2_000, 3, 4); // PID reused, later start
        assert_ne!(a.incarnation, b.incarnation);
    }

    #[test]
    fn test_starting_state_is_never_ok() {
        let hb = Heartbeat::new(1, 5, 1, 2);
        let json = hb.to_json();
        assert!(json.contains("\"state\":\"starting\""));
        assert!(json.contains("\"generation\":0"));
        assert!(json.contains("\"trust_ok\":false") && json.contains("\"risk_ok\":false"));
    }

    #[test]
    fn test_write_errors_mark_only_affected_signal() {
        let mut hb = Heartbeat::new(1, 5, 1, 2);
        hb.complete_cycle(CycleOutcome { hosts: 2, risk_write_errors: 1, ..Default::default() }, 10, 20);
        let json = hb.to_json();
        assert!(json.contains("\"trust_ok\":true") && json.contains("\"risk_ok\":false"));

        hb.complete_cycle(CycleOutcome { hosts: 2, stats_read_errors: 1, ..Default::default() }, 11, 21);
        let json = hb.to_json();
        assert!(json.contains("\"trust_ok\":false") && json.contains("\"risk_ok\":false"));
    }

    #[test]
    fn test_flow_event_input_problems_mark_only_risk() {
        // Heartbeat keeps advancing, but risk must not be reported healthy on incomplete input.
        let ok = CycleOutcome { hosts: 1, flow_consumers_alive: 4, flow_consumers_expected: 4, ..Default::default() };
        assert!(ok.trust_ok() && ok.risk_ok());
        let dead_consumer = CycleOutcome { flow_consumers_alive: 3, ..ok };
        assert!(dead_consumer.trust_ok() && !dead_consumer.risk_ok());
        let lost = CycleOutcome { flow_events_lost: 12, ..ok };
        assert!(lost.trust_ok() && !lost.risk_ok());
    }

    #[test]
    fn test_stop_keeps_generation_and_marks_stopped() {
        let mut hb = fixture_heartbeat();
        hb.stop(999, 1);
        let json = hb.to_json();
        assert!(json.contains("\"state\":\"stopped\"") && json.contains("\"generation\":7"));
    }

    #[test]
    fn test_write_atomic_replaces_without_leftovers() {
        let dir = std::env::temp_dir().join(format!("adg-hb-test-{}", std::process::id()));
        let path = dir.join("sub").join("heartbeat.json");
        write_atomic(&path, "first\n").unwrap();
        write_atomic(&path, "second\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second\n");
        let leftovers: Vec<_> = fs::read_dir(path.parent().unwrap()).unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
