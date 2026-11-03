//! kogany (S5-K11): a newly responded peer ends the syncer's restart sleep.

use std::time::Duration;

use tokio::sync::watch;
use zakura_network::AddressMetrics;

use crate::components::sync::restart_sleep;

fn metrics(responded: usize) -> AddressMetrics {
    AddressMetrics {
        responded,
        ..AddressMetrics::default()
    }
}

#[tokio::test(start_paused = true)]
async fn new_responded_peer_wakes_restart_sleep() {
    let (tx, mut rx) = watch::channel(metrics(2));
    let start = tokio::time::Instant::now();
    let sleeper =
        tokio::spawn(async move { restart_sleep(Duration::from_secs(60), Some(&mut rx)).await });
    tokio::time::sleep(Duration::from_secs(1)).await;
    // a change that is not a new peer does not wake it
    tx.send_replace(AddressMetrics {
        failed: 1,
        ..metrics(2)
    });
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!sleeper.is_finished());
    tx.send_replace(metrics(3));
    assert!(sleeper.await.expect("no panic"));
    assert!(start.elapsed() < Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn restart_sleep_runs_full_delay_without_new_peer() {
    let (tx, mut rx) = watch::channel(metrics(2));
    let start = tokio::time::Instant::now();
    assert!(!restart_sleep(Duration::from_secs(5), Some(&mut rx)).await);
    assert!(start.elapsed() >= Duration::from_secs(5));
    drop(tx);
    assert!(!restart_sleep(Duration::from_secs(5), None).await);
}

/// kogany (S5-K12): a gap notified during a round (before the sleep starts) ends the next
/// restart sleep at once; without a notifier the wait never ends.
#[tokio::test(start_paused = true)]
async fn gossip_gap_ends_restart_sleep() {
    use crate::components::sync::gossip_gap_notified;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    notify.notify_one();
    let start = tokio::time::Instant::now();
    tokio::select! {
        _ = restart_sleep(Duration::from_secs(60), None) => panic!("slept the full delay"),
        _ = gossip_gap_notified(Some(&notify)) => {}
    }
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(
        tokio::time::timeout(Duration::from_secs(5), gossip_gap_notified(None))
            .await
            .is_err()
    );
}
