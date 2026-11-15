use super::*;

#[tokio::test]
async fn writer_failure_reaches_supervision_while_read_clones_hold_the_join_handle() {
    use tower::ServiceExt;

    let network = Network::new_regtest(Default::default());
    let (_state, read, _tip, _tip_change) = crate::service::init_test_services(&network).await;
    let mut read_clone = read.clone();
    assert!(read_clone.writer_failure().is_none());
    let observer = read.clone();
    let supervisor = tokio::spawn(async move { observer.wait_for_writer_failure().await });
    tokio::task::yield_now().await;
    read.block_write_failure.set(BlockWriteTaskFailure::runtime(
        "incoherent ready VCT auxiliary window",
        "missing exact roots",
    ));
    let error = tokio::time::timeout(Duration::from_secs(5), supervisor)
        .await
        .expect("writer failure wakes supervision without joining the writer")
        .expect("the supervision task returns normally");
    assert!(error.to_string().contains("missing exact roots"));
    assert!(read_clone
        .writer_failure()
        .unwrap()
        .to_string()
        .contains("missing exact roots"));
    assert!(read_clone.ready().await.is_err());
    assert!(read
        .wait_for_writer_failure()
        .await
        .to_string()
        .contains("missing exact roots"));
}

#[tokio::test]
async fn writer_failure_wakes_all_waiters_and_survives_late_subscription() {
    let failure = Arc::new(BlockWriteFailure::default());
    let first = failure.clone();
    let second = failure.clone();
    let first = tokio::spawn(async move { first.wait().await });
    let second = tokio::spawn(async move { second.wait().await });
    tokio::task::yield_now().await;
    failure.set(BlockWriteTaskFailure::runtime(
        "incoherent roots",
        "wrong hash",
    ));
    failure.set(BlockWriteTaskFailure::panic());
    tokio::time::timeout(Duration::from_secs(5), async {
        for observed in [
            first.await.unwrap(),
            second.await.unwrap(),
            failure.wait().await,
        ] {
            assert!(observed
                .to_string()
                .contains("incoherent roots: wrong hash"));
        }
    })
    .await
    .expect("writer failure wakes every supervisor");
}

#[test]
fn abnormal_writer_exits_expose_stable_health_failures() {
    let failure = BlockWriteTaskFailure::runtime("runtime context", "store failure");
    let exit = BlockWriteTaskExit::HeaderChainRuntimeFailed(failure.clone());

    assert_eq!(
        exit.failure()
            .expect("a runtime failure is visible to every state clone")
            .to_string(),
        failure.to_string()
    );
    assert!(BlockWriteTaskExit::Completed.failure().is_none());
}

#[test]
fn header_chain_finalization_errors_become_failed_writer_exits() {
    let error = CommitBlockError::HeaderChainError {
        error: "durable header transition failed".to_owned(),
    }
    .into();

    let BlockWriteTaskExit::HeaderChainRuntimeFailed(failure) =
        header_chain_finalization_failure(error)
    else {
        panic!("a header-chain finalization failure must not report clean shutdown");
    };
    assert!(failure
        .to_string()
        .contains("header-chain reorg-limit finalization failed"));
}

#[test]
#[should_panic(expected = "unexpected finalized block commit error")]
fn legacy_finalization_invariant_failures_remain_explicit_panics() {
    let error = CommitCheckpointVerifiedError::from(CommitBlockError::WriteTaskExited);
    let _ = header_chain_finalization_failure(error);
}

/// kogany (beta3 R1, decision note `reorg-parity.md` requirement 2): a refused reorganisation
/// survives a restart with the non-finalized backup on and off. The record beside the state
/// database stops the writer at once on the next start, the failure is ycashd's message, and
/// it reaches the daemon's supervision, which shuts the node down. The record stays until an
/// operator removes it; without one the writer runs. (`reorg_parity.py` restarts a real node.)
#[cfg(feature = "ycash")]
#[tokio::test(flavor = "multi_thread")]
async fn recorded_reorg_refusal_stops_the_writer_at_startup() {
    use crate::service::non_finalized_state::reorg_guard;

    let _init_guard = zakura_test::init();
    let network = Network::new_regtest(Default::default());
    let cache_dir = tempfile::tempdir().expect("a temporary directory");
    let refused = reorg_guard::RefusedReorg {
        rollback: 100,
        old_tip: (block::Height(300), block::Hash([1; 32])),
        new_tip: (block::Height(301), block::Hash([2; 32])),
        fork: (block::Height(200), block::Hash([3; 32])),
    };
    let sentence =
        "A block chain reorganization has been detected that would roll back 100 blocks!";

    for should_backup_non_finalized_state in [true, false] {
        // A state database is opened once per process, so each start has its own directory.
        let config_of = |name: &str| {
            let config = Config {
                cache_dir: cache_dir
                    .path()
                    .join(format!("{name}-{should_backup_non_finalized_state}")),
                ephemeral: false,
                should_backup_non_finalized_state,
                ..Config::default()
            };
            let recorded = reorg_guard::recorded_for(&config, &network);
            (config, recorded)
        };
        let start = |name: &str, refuse: bool| {
            let config = config_of(name).0;
            let db_path = config.db_path(
                crate::constants::STATE_DATABASE_KIND,
                crate::constants::state_database_format_version_in_code().major,
                &network,
            );
            if refuse {
                // What the writer does when it refuses a reorganisation.
                std::fs::create_dir_all(&db_path).expect("the database directory is created");
                let exit = refuse_reorg(&db_path, refused);
                let failure = exit.failure().expect("a refusal is a writer failure");
                assert!(failure.to_string().contains(sentence), "{failure}");
                assert_eq!(
                    reorg_guard::recorded(&db_path).as_deref(),
                    Some(refused.to_string().as_str())
                );
            }
            let network = network.clone();
            async move {
                let (state, read, _tip, _tip_change) =
                    crate::service::StateService::new(config, &network, block::Height::MAX, 0)
                        .await
                        .expect("the state opens");
                (state, read, db_path)
            }
        };

        // No record: the writer runs.
        let (_running, read, db_path) = start("running", false).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(500), read.wait_for_writer_failure())
                .await
                .is_err(),
            "the writer runs without a record"
        );
        assert_eq!(reorg_guard::recorded(&db_path), None);
        assert_eq!(config_of("running").1, None);

        // A record: the writer stops at once with the recorded message, and leaves the record.
        let (_refused, read, db_path) = start("refused", true).await;
        let failure = tokio::time::timeout(Duration::from_secs(30), read.wait_for_writer_failure())
            .await
            .expect("the writer stops while a refusal is on record");
        assert!(failure.to_string().contains(sentence), "{failure}");
        assert_eq!(
            reorg_guard::recorded(&db_path).as_deref(),
            Some(refused.to_string().as_str())
        );
        // What the node checks before it starts: the same record, at the same path.
        assert_eq!(
            config_of("refused").1,
            Some((reorg_guard::refusal_path(&db_path), refused.to_string()))
        );
    }

    // An ephemeral state starts empty: it has no record.
    assert_eq!(
        reorg_guard::recorded_for(&Config::ephemeral(), &network),
        None
    );
}
