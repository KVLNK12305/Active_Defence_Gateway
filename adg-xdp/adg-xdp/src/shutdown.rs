//! Cooperative shutdown for the blocking FLOW_EVENTS consumers.
//!
//! The consumers run on `spawn_blocking` threads. Dropping a tokio runtime waits for every blocking
//! thread, so a consumer loop without an exit condition made the daemon hang forever after
//! Ctrl-C (observed live: main thread in futex wait, 8 consumer threads sleeping).

use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Poll for work until `stop` is set. `idle` bounds how long a worker can take to notice it.
pub fn consumer_loop<F: FnMut()>(stop: &AtomicBool, mut poll_once: F, idle: Duration) {
    while !stop.load(Ordering::SeqCst) {
        poll_once();
        std::thread::sleep(idle);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownSummary {
    pub completed: usize,
    pub panicked: usize,
    pub unfinished: usize,
}

impl ShutdownSummary {
    #[allow(dead_code)]
    pub fn is_clean(&self) -> bool {
        self.unfinished == 0 && self.panicked == 0
    }
}

/// Wait for all workers until `deadline`. Returns a summary of task termination outcomes.
pub async fn join_with_deadline(
    handles: Vec<tokio::task::JoinHandle<()>>,
    deadline: Duration,
) -> ShutdownSummary {
    let end = Instant::now() + deadline;
    let mut summary = ShutdownSummary::default();
    for handle in handles {
        let remaining = end.saturating_duration_since(Instant::now());
        match tokio::time::timeout(remaining, handle).await {
            Ok(join_res) => match join_res {
                Ok(()) => summary.completed += 1,
                Err(err) => {
                    if err.is_panic() {
                        summary.panicked += 1;
                        log::error!("FLOW_EVENTS consumer panicked: {:?}", err);
                    } else {
                        summary.completed += 1;
                    }
                }
            },
            Err(_) => {
                summary.unfinished += 1;
                log::warn!("FLOW_EVENTS consumer did not finish within deadline");
            }
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicU64, mpsc, Arc};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap()
    }

    #[test]
    fn test_consumers_stop_and_runtime_drop_completes() {
        // Reproduces the live failure path: blocking consumers on a real runtime, then the runtime
        // is dropped. Before the fix the drop never returned.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let rt = runtime();
            let stop = Arc::new(AtomicBool::new(false));
            let polls = Arc::new(AtomicU64::new(0));
            let started = Instant::now();
            let summary = rt.block_on(async {
                let handles: Vec<_> = (0..8)
                    .map(|_| {
                        let (s, p) = (stop.clone(), polls.clone());
                        tokio::task::spawn_blocking(move || {
                            consumer_loop(&s, || { p.fetch_add(1, Ordering::Relaxed); }, Duration::from_millis(10))
                        })
                    })
                    .collect();
                tokio::time::sleep(Duration::from_millis(50)).await;
                stop.store(true, Ordering::SeqCst);
                join_with_deadline(handles, Duration::from_secs(3)).await
            });
            drop(rt);
            tx.send((summary, polls.load(Ordering::Relaxed), started.elapsed())).unwrap();
        });
        let (summary, polls, elapsed) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("runtime did not shut down within 5 s (consumers kept it alive)");
        assert_eq!(summary.unfinished, 0);
        assert_eq!(summary.completed, 8);
        assert_eq!(summary.panicked, 0);
        assert!(summary.is_clean());
        assert!(polls > 0, "consumers never ran");
        assert!(elapsed < Duration::from_secs(2), "shutdown took {:?}", elapsed);
    }

    #[test]
    fn test_stuck_worker_is_reported_at_deadline() {
        // A worker that ignores the flag must not block the caller past the deadline.
        let rt = runtime();
        let started = Instant::now();
        let summary = rt.block_on(async {
            let stuck = tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_secs(2)));
            join_with_deadline(vec![stuck], Duration::from_millis(100)).await
        });
        assert_eq!(summary.unfinished, 1);
        assert_eq!(summary.completed, 0);
        assert!(!summary.is_clean());
        assert!(started.elapsed() < Duration::from_secs(1));
        rt.shutdown_timeout(Duration::from_millis(10)); // don't wait for the stuck thread
    }

    #[test]
    fn test_panicking_worker_is_observed_and_counted() {
        let rt = runtime();
        let summary = rt.block_on(async {
            let h = tokio::task::spawn_blocking(|| panic!("simulated consumer crash"));
            join_with_deadline(vec![h], Duration::from_secs(1)).await
        });
        assert_eq!(summary.unfinished, 0);
        assert_eq!(summary.panicked, 1);
        assert_eq!(summary.completed, 0);
        assert!(!summary.is_clean());
    }
}
