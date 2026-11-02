//! The index view of a running node (kogany plan W7-b): [`LiveIndex`], a [`YedIndexView`] over
//! `zakura_state`'s best-chain YED snapshot (`zakura_state::yed::YedSnapshot`, which implements
//! `kogany_yellowback::state::YedRead`), with the node's attestation pool and `REF_LAG`.
//!
//! Every row is ycash6's derivation in `src/rpc/yellowback.cpp` at `65cb4ae0f` (`VaultToJSON`,
//! `PushTxLogV3`, `EstimateClaim`, `yed_listtokens`, `yed_listminers`, `yed_listattestors`,
//! `yed_getselection`, `yed_estimatecollateral`) and `src/yellowback/{index,policy}.cpp`
//! (`AuditIndexRecords`, `BuildBundleInfoLocked`, `MintPolicyRefusal`), over the same state
//! machine (`kogany_yellowback::state`). What ycashd reads beyond the index (the mempool, a
//! transaction's bytes, a block) is the async state's ([`super::live::LiveYedState`]).

use std::sync::{Arc, Mutex};

use kogany_vault::{state::VaultTx, Hash32, OutPoint};
use kogany_yellowback::{
    attest::{
        age_origin, attestation_valid, attestor_weight, bundle_stat, encode_bundle,
        outpoint_selector,
        price::{HALT_DIVERGENCE, HALT_GLOBAL_RATIO, HALT_NOT_ACTIVE, HALT_NO_PRICE},
        registry::{
            AttestState as RecordAttestState, AttestStatus as RecordStatus, AttestorRecord,
            AttestorStatus as RecordAttestorStatus, ATTESTOR_FLAG_EVICTED,
        },
        selected, Attestation as KAttestation, Bundle,
    },
    codecs::{
        payload::{find_payload, Payload},
        script::{find_carrier_input, holder_key, is_compressed_key, yed_vault_script_at, Holder},
    },
    math::{
        attest_fee_zat, claimant_max_zat, is_underwater, min_ratio_bps, price_combine,
        protocol_fee_cents, protocol_fee_zat, required_collateral_rounded, residual_min_zat,
        residual_zat, seat_weight, supply_cap_cents, BPS, DEFAULT_COLLATERAL_GRANULARITY, U256,
    },
    params::{MicroUsd, Params, COIN, LOCKTIME_THRESHOLD, MAX_MONEY},
    state::{
        armed_at, block_hash_at, cancels_required, default_payee, eligible_payees,
        lookups::selection_basis,
        penalized, registered,
        view::{attestor_of, attestors_of},
        IntentRole, NoticeRecord, PayeePolicy as StatePayeePolicy, Snapshot, Table, TxLogRecord,
        TxLogType, VaultRecord, VaultStatus as RecordVaultStatus, YedKey, YedRead, YedRecord,
    },
};

use super::pool::AttestationPool;
use super::state::*;

/// The index at the best chain's tip ([`YedIndexView`] over the state snapshot), with this
/// node's attestation pool and `REF_LAG` (`-yellowbackmintlag`).
pub struct LiveIndex {
    snap: zakura_state::yed::YedSnapshot,
    params: Params,
    ref_lag: i64,
    pool: Arc<Mutex<AttestationPool>>,
}

impl LiveIndex {
    /// The view of `snap` under `params`, with the node's `REF_LAG` and an empty pool.
    pub fn new(snap: zakura_state::yed::YedSnapshot, params: Params) -> Self {
        Self::with_pool(
            snap,
            params,
            i64::from(super::fees::node_policy().ref_lag),
            Arc::default(),
        )
    }

    /// The view of `snap` under `params` with the node's `REF_LAG` and attestation pool.
    pub fn with_pool(
        snap: zakura_state::yed::YedSnapshot,
        params: Params,
        ref_lag: i64,
        pool: Arc<Mutex<AttestationPool>>,
    ) -> Self {
        Self {
            snap,
            params,
            ref_lag,
            pool,
        }
    }

    /// The state snapshot.
    pub fn snap(&self) -> &zakura_state::yed::YedSnapshot {
        &self.snap
    }

    fn read(&self) -> &dyn YedRead {
        &self.snap
    }

    fn tip_height(&self) -> i64 {
        self.snap.index_tip().map_or(-1, |t| i64::from(t.height))
    }

    fn pool(&self) -> std::sync::MutexGuard<'_, AttestationPool> {
        self.pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `PoolFreshAt(seq, refHeight)`.
    fn pool_fresh_at(&self, seq: u16, ref_height: i64) -> bool {
        let p = &self.params;
        self.pool()
            .freshest(
                seq,
                ref_height,
                i64::from(p.attest_max_age),
                i64::from(p.start_height),
            )
            .is_some()
    }

    /// The stored `Snapshots[h]` (no virtual snapshot), `None` outside the table.
    fn stored_snapshot(&self, h: i64) -> Option<Snapshot> {
        self.snap.snapshot_at(h)
    }

    /// `BuildBundleInfoLocked` (ycash6 `src/yellowback/index.cpp`): the bundle this node would
    /// build for `(ref_height, selector)` from its pool.
    fn build_bundle_info(&self, ref_height: i64, selector: &[u8]) -> BuiltInfo {
        let p = &self.params;
        let r = self.read();
        let m_select = usize::try_from(p.m_select.max(0)).unwrap_or(usize::MAX);
        let basis = selection_basis(r, p, ref_height);
        let registry = kogany_yellowback::state::RegistryView(r);
        let selected = selected(basis.as_ref(), &registry, p, ref_height, selector);
        let attest = if ref_height >= i64::from(p.start_height) && ref_height >= 0 {
            self.stored_snapshot(ref_height).map(|s| s.attest)
        } else {
            None
        }
        .unwrap_or_default();
        let mut info = BuiltInfo {
            armed: armed_at(r, p, ref_height),
            selected: selected.clone(),
            ..BuiltInfo::default()
        };
        let mut chosen: Vec<(u16, KAttestation)> = Vec::new();
        for seq in selected {
            let att = self.pool().freshest(
                seq,
                ref_height,
                i64::from(p.attest_max_age),
                i64::from(p.start_height),
            );
            let usable = att.and_then(|att| {
                let rec = attestor_of(r, seq)?;
                let hash = block_hash_at(r, p, i64::from(att.cited_height))?;
                let katt = k_attestation(&att);
                // A pooled attestation was verified at arrival; after a reorg its cited block may
                // carry another hash (R9).
                attestation_valid(
                    &katt,
                    &rec.attestor_pub_key,
                    &hash,
                    Some(zakura_state::yed::module::node_yed_sig_cache()),
                )
                .then_some(katt)
            });
            match usable {
                Some(katt) => chosen.push((seq, katt)),
                None => info.missing.push(seq),
            }
        }
        chosen.sort_by_key(|(seq, _)| *seq);
        let mut weights = Vec::with_capacity(chosen.len());
        for (seq, att) in chosen {
            info.seqs.push(seq);
            info.atts.push(att);
            weights.push(attestor_of(r, seq).map_or(U256::ZERO, |rec| {
                attestor_weight(&rec, &attest, p, ref_height)
            }));
        }
        info.sufficient = info.seqs.len() >= m_select && !info.seqs.is_empty();
        if info.sufficient {
            let (a_mint, a_claim) =
                bundle_stat(&info.atts, &weights, m_select, p.q_low_bps, p.q_high_bps);
            info.a_mint = a_mint;
            info.a_claim = a_claim;
        }
        info
    }

    /// `EstimateClaim` (ycash6 `src/rpc/yellowback.cpp`): RED-4 at the tip by either clause.
    fn estimate_claim(&self, out: &OutPoint, v: &VaultRecord, tip: i64) -> ClaimEstimate {
        let p = &self.params;
        let r = self.read();
        let ref_height = tip;
        let mut e = ClaimEstimate {
            armed: ref_height >= i64::from(p.start_height) && armed_at(r, p, ref_height),
            ..ClaimEstimate::default()
        };
        let mature = tip >= i64::from(v.app_height) && v.status == RecordVaultStatus::Active;
        let residual_min = residual_min_zat(v.p_mint, p);
        if !e.armed {
            let snap = if tip >= i64::from(p.start_height) {
                self.stored_snapshot(tip)
            } else {
                None
            };
            e.p_claim = snap.and_then(|s| s.pclaim());
            e.claimable = mature
                && is_underwater(
                    v.collateral_zat,
                    e.p_claim,
                    v.minted_cents,
                    p.claim_threshold_bps,
                );
            e.claim_path = if e.claimable { "a" } else { "" };
            if let (true, Some(price)) = (e.claimable, e.p_claim) {
                e.residual_zat = residual_zat(
                    v.collateral_zat,
                    claimant_max_zat(v.minted_cents, p.claim_threshold_bps, price),
                );
            }
            if e.residual_zat < residual_min {
                e.residual_zat = 0;
            }
            return e;
        }
        let snap = self.stored_snapshot(ref_height);
        let x_claim = snap.as_ref().and_then(Snapshot::pclaim);
        let built = self.build_bundle_info(ref_height, &outpoint_selector(out));
        let bundle_ok = built.sufficient && built.a_claim.is_some();
        e.attest_fee_zat = attest_fee_zat(
            protocol_fee_zat(v.minted_cents, v.p_mint, p).unwrap_or(MAX_MONEY),
            p.attest_fee_bps,
        );
        let p_emerg = if bundle_ok {
            let c = price_combine(
                snap.as_ref().and_then(Snapshot::pmint),
                x_claim,
                built.a_mint,
                built.a_claim,
            );
            e.p_claim = c.p_claim;
            c.p_emerg
        } else {
            e.p_claim = x_claim;
            x_claim
        };
        let under_a = is_underwater(
            v.collateral_zat,
            e.p_claim,
            v.minted_cents,
            p.claim_threshold_bps,
        );
        let notice = r.notice(out);
        let persisted = notice.is_some_and(|n| {
            let age = ref_height.saturating_sub(i64::from(n.ref_height));
            age >= i64::from(p.emergency_persist) && age <= i64::from(p.emergency_notice_ttl)
        });
        let under_b = persisted
            && is_underwater(
                v.collateral_zat,
                p_emerg,
                v.minted_cents,
                p.emergency_ratio_bps,
            );
        e.claimable = mature && (under_a || under_b);
        if bundle_ok {
            e.claim_path = if under_a {
                "a"
            } else if under_b {
                "b"
            } else {
                ""
            };
        }
        // RED-5b: path (a) caps at pClaim; path (b) caps at pEmerg (W3-Y-5, A1).
        let cap_price = if under_a { e.p_claim } else { p_emerg };
        if let (true, Some(price)) = (e.claimable, cap_price) {
            let margin = if under_a {
                p.claim_threshold_bps
            } else {
                i32::try_from(BPS).unwrap_or(i32::MAX)
            };
            e.residual_zat = residual_zat(
                v.collateral_zat,
                claimant_max_zat(v.minted_cents, margin, price),
            );
            if e.residual_zat < residual_min {
                e.residual_zat = 0;
            }
        }
        e
    }

    /// `PushNoticeFields`: the standing notice of an ACTIVE vault, `(height, emergencyOpenAt)`.
    fn notice_fields(&self, out: &OutPoint, v: &VaultRecord) -> Option<(i64, i64)> {
        if v.status != RecordVaultStatus::Active {
            return None;
        }
        self.read().notice(out).map(|n| {
            (
                i64::from(n.height),
                i64::from(n.ref_height).saturating_add(i64::from(self.params.emergency_persist)),
            )
        })
    }

    /// `VaultToJSON`'s derived row.
    fn vault_row(&self, out: &OutPoint, v: &VaultRecord, tip_snap: bool) -> VaultRow {
        let p = &self.params;
        let tip = self.tip_height();
        let owner = v.owner();
        let claimable = v.status == RecordVaultStatus::Active
            && tip >= i64::from(v.app_height)
            && tip_snap
            && self.estimate_claim(out, v, tip).claimable;
        let intents_all = self.read().intents();
        let (intents, refund_holder) = if v.status == RecordVaultStatus::Claiming {
            let mut refund = None;
            let rows = intents_all
                .iter()
                .filter(|(_, ir)| ir.vault == *out)
                .map(|(o, ir)| {
                    if ir.role == IntentRole::Claimant && !ir.refund_script.is_empty() {
                        refund = Some(ir.refund_script.clone());
                    }
                    VaultIntent {
                        outpoint: *o,
                        claimant: ir.role == IntentRole::Claimant,
                        height: i64::from(ir.height),
                        release_height: i64::from(ir.height)
                            .saturating_add(i64::from(p.claim_delay)),
                    }
                })
                .collect();
            (Some(rows), refund)
        } else {
            (None, None)
        };
        let held: Vec<OutPoint> = intents_all
            .iter()
            .filter(|(_, ir)| ir.role == IntentRole::Residual && ir.held_by == *out)
            .map(|(o, _)| *o)
            .collect();
        VaultRow {
            txid: out.txid,
            status: vault_status(v.status),
            owner,
            term_class: v.term_class,
            lock_height: i64::from(v.lock_height),
            claim_height: i64::from(v.claim_height),
            collateral_zat: v.collateral_zat,
            minted_cents: v.minted_cents,
            mint_height: i64::from(v.mint_height),
            ref_height: i64::from(v.ref_height),
            fee_paid_zat: v.fee_paid_zat,
            p_mint: v.p_mint,
            closed: (!v.is_open()).then_some((i64::from(v.close_height), v.closing_txid)),
            burned_cents: v.burned_cents,
            unbacked: v.unbacked,
            cancel_count: i64::from(v.cancel_count),
            cancels_required: cancels_required(v, p, tip.saturating_add(1)),
            cancel_quiet_until: (v.last_cancel_height > 0)
                .then(|| i64::from(v.last_cancel_height).saturating_add(i64::from(p.cancel_quiet))),
            claimable,
            underwater_at: if v.status == RecordVaultStatus::Voided {
                None
            } else {
                underwater_at(v, p)
            },
            void_reason: v.void_reason.clone(),
            script_pubkey: yed_vault_script_at(
                p,
                &owner,
                i64::from(v.owner_height),
                i64::from(v.app_height),
            )
            .unwrap_or_default(),
            intents,
            refund_holder,
            held_residuals: Some(held),
            notice: self.notice_fields(out, v),
            spend_txid: None,
        }
    }

    /// The reference height a transaction's rules read (`RefHeightOf`): a MINT's vault record,
    /// else its REDEEM / CLAIM_NOTICE / MINT payload.
    fn ref_height_of(&self, txid: &Hash32, l: &TxLogRecord, tx: Option<&VaultTx>) -> Option<i64> {
        if l.tx_type == TxLogType::Mint {
            if let Some(v) = self.read().vault(&OutPoint { txid: *txid, n: 0 }) {
                return Some(i64::from(v.ref_height));
            }
        }
        let tx = tx?;
        let scripts: Vec<&[u8]> = tx
            .outputs
            .iter()
            .map(|o| o.script_pubkey.as_slice())
            .collect();
        match find_payload(&scripts)?.payload {
            Payload::Redeem(r) => Some(i64::from(r.ref_height)),
            Payload::ClaimNotice(n) => Some(i64::from(n.ref_height)),
            Payload::Mint(m) => Some(i64::from(m.ref_height)),
            _ => None,
        }
    }

    /// `TxLogToJSON` with `PushTxLogV3`: `tx` is the transaction when it could be fetched (the
    /// carrier input, a REDEEM's reference height).
    pub fn tx_info_row(&self, txid: &Hash32, l: &TxLogRecord, tx: Option<&VaultTx>) -> TxInfoRow {
        let p = &self.params;
        let r = self.read();
        let ref_height = self.ref_height_of(txid, l, tx);
        let (mut x_mint, mut x_claim, mut armed) = (None, None, false);
        if let Some(s) = ref_height.and_then(|h| kogany_yellowback::state::snapshot_at(r, p, h)) {
            x_mint = s.pmint();
            x_claim = s.pclaim();
            armed = p.is_armed(s.attest.is_armed());
        }
        let (mut p_mint, mut p_claim) = (x_mint, x_claim);
        if armed && l.a_mint().is_some() && l.a_claim().is_some() {
            let c = price_combine(x_mint, x_claim, l.a_mint(), l.a_claim());
            p_mint = c.p_mint;
            p_claim = c.p_claim;
        }
        let mut bundle_seqs = l.bundle_seqs.clone();
        bundle_seqs.sort_unstable();
        let attest_payee = if l.has_attest_payee {
            attestor_of(r, l.attest_payee).and_then(|rec| bond_key_hash(&rec))
        } else {
            None
        };
        let (carrier_vin, bundle_source) = tx
            .and_then(|tx| {
                let sigs: Vec<&[u8]> = tx.inputs.iter().map(|i| i.script_sig.as_slice()).collect();
                find_carrier_input(&sigs, l.tx_type == TxLogType::Redeem).ok()
            })
            .map_or((-1, String::new()), |vin| {
                (
                    i64::try_from(vin).unwrap_or(i64::MAX),
                    "scriptsig".to_owned(),
                )
            });
        TxInfoRow {
            height: i64::from(l.height),
            kind: type_lower(l.tx_type).to_owned(),
            path: l.path.clone(),
            verdict: l.verdict.clone(),
            yed_in: l.yed_in,
            yed_out: l.yed_out,
            burned: l.burned,
            fee_zat: l.fee_zat,
            payee: l.has_payee.then_some(l.payee),
            assigned: l.assigned.iter().map(|a| (a.outpoint.n, a.cents)).collect(),
            spent_tokens: l.spent_tokens.iter().map(|a| a.outpoint).collect(),
            closed_vaults: l.closed_vaults.clone(),
            reopened_vaults: l.reopened_vaults.clone(),
            expired: false,
            x_mint,
            x_claim,
            a_mint: l.a_mint(),
            a_claim: l.a_claim(),
            p_mint,
            p_claim,
            bundle_seqs,
            attest_fee_zat: l.attest_fee_zat,
            attest_payee,
            residual_zat: l.residual_zat,
            claim_path: l.claim_path.clone(),
            notice: l.notice,
            carrier_vin,
            bundle_source,
            seq: matches!(
                l.tx_type,
                TxLogType::AttestorRegister | TxLogType::AttestorSetAct
            )
            .then_some(l.attestor_seq),
        }
    }

    /// `MintPolicyRefusal` (MINTPOL-1, ycash6 `src/yellowback/policy.cpp`): the identifier
    /// `yed_mint` would refuse with at `R`. kogany has no wallet and the RPC no mempool access,
    /// so the pending mints of `MempoolMintCents` count zero here.
    fn mint_policy_refusal(
        &self,
        ref_height: i64,
        term_class: usize,
        cents: i64,
    ) -> Option<&'static str> {
        let p = &self.params;
        let r = self.read();
        let Some(s) = kogany_yellowback::state::snapshot_at(r, p, ref_height) else {
            return Some("mintpol-not-active");
        };
        if s.halt_mask & HALT_NOT_ACTIVE != 0 {
            return Some("mintpol-not-active");
        }
        if s.halt_mask & HALT_NO_PRICE != 0 {
            return Some("mintpol-no-price");
        }
        let base = p.base_ratio_bps.get(term_class).copied().unwrap_or(0);
        if s.halt_mask & HALT_GLOBAL_RATIO != 0 && base < p.recap_ratio_bps {
            return Some("mintpol-global-ratio");
        }
        if s.halt_mask & HALT_DIVERGENCE != 0 {
            return Some("mintpol-divergence");
        }
        if s.halt_mask & !HALT_GLOBAL_RATIO != 0 {
            return Some("mintpol-not-active");
        }
        if p.mint_requires_armed && !armed_at(r, p, ref_height) {
            return Some("mintpol-unarmed");
        }
        let x_mint = s.pmint()?;
        let supply = r.totals().supply_cents;
        let cap = supply_cap_cents(s.issued_zat, Some(x_mint), p.supply_cap_bps);
        if cap.is_some_and(|cap| supply.saturating_add(cents) > cap) && base < p.recap_ratio_bps {
            return Some("mintpol-cap");
        }
        None
    }
}

/// What `BuildBundleInfoLocked` reports.
#[derive(Clone, Debug, Default)]
struct BuiltInfo {
    armed: bool,
    selected: Vec<u16>,
    seqs: Vec<u16>,
    missing: Vec<u16>,
    atts: Vec<KAttestation>,
    sufficient: bool,
    a_mint: Option<MicroUsd>,
    a_claim: Option<MicroUsd>,
}

impl BuiltInfo {
    /// `BuiltBundle::InsufficientMessage`.
    fn insufficient(&self) -> YedError {
        let missing: Vec<String> = self.missing.iter().map(u16::to_string).collect();
        YedError::new(
            YedErrorKind::Rejected,
            "bundle-insufficient",
            format!(
                "{} of {} selected attestors have a fresh attestation; missing seq {}",
                self.seqs.len(),
                self.selected.len(),
                missing.join(",")
            ),
        )
    }
}

/// What `EstimateClaim` reports.
#[derive(Clone, Debug, Default)]
struct ClaimEstimate {
    armed: bool,
    p_claim: Option<MicroUsd>,
    claimable: bool,
    claim_path: &'static str,
    residual_zat: i64,
    attest_fee_zat: i64,
}

fn k_attestation(a: &Attestation) -> KAttestation {
    KAttestation {
        seq: a.seq,
        price_micro_usd: a.price_micro_usd,
        cited_height: a.cited_height,
        sig: a.sig,
    }
}

fn price(v: i64) -> Option<i64> {
    (v != 0).then_some(v)
}

fn vault_status(s: RecordVaultStatus) -> VaultStatus {
    match s {
        RecordVaultStatus::Active => VaultStatus::Active,
        RecordVaultStatus::Voided => VaultStatus::Void,
        RecordVaultStatus::Closed => VaultStatus::Closed,
        RecordVaultStatus::Claimed => VaultStatus::Claimed,
        RecordVaultStatus::Claiming => VaultStatus::Claiming,
    }
}

fn attestor_status(s: RecordAttestorStatus) -> AttestorStatus {
    match s {
        RecordAttestorStatus::Pending => AttestorStatus::Pending,
        RecordAttestorStatus::Eligible => AttestorStatus::Eligible,
        RecordAttestorStatus::Dormant => AttestorStatus::Dormant,
        RecordAttestorStatus::Ejected => AttestorStatus::Ejected,
        RecordAttestorStatus::Withdrawn => AttestorStatus::Withdrawn,
    }
}

fn attest_state(a: RecordAttestState) -> AttestState {
    AttestState {
        status: match a.status {
            RecordStatus::Unarmed => AttestStatus::Unarmed,
            RecordStatus::Triggered => AttestStatus::Triggered,
            RecordStatus::Armed => AttestStatus::Armed,
        },
        trigger_height: i64::from(a.trigger_height),
        arm_height: i64::from(a.arm_height),
    }
}

/// `TypeLower`.
fn type_lower(t: TxLogType) -> &'static str {
    match t {
        TxLogType::Mint => "mint",
        TxLogType::Transfer => "transfer",
        TxLogType::Redeem => "redeem",
        TxLogType::AttestorRegister => "register",
        TxLogType::ClaimNotice => "notice",
        TxLogType::Equivocation => "equivocation",
        TxLogType::AttestorRevive => "revive",
        TxLogType::ClaimRelease => "claim_release",
        TxLogType::ClaimCancel => "claim_cancel",
        TxLogType::AttestorSetAct => "set_act",
        TxLogType::None => "none",
    }
}

/// The TxLog type name ycashd prints (`TypeLower`).
pub fn tx_type_name(t: TxLogType) -> &'static str {
    type_lower(t)
}

/// `BondKeyAddress`'s key: the Hash160 of a valid bond key.
fn bond_key_hash(rec: &AttestorRecord) -> Option<[u8; 20]> {
    is_compressed_key(&rec.bond_pub_key.0)
        .then(|| kogany_vault::template::hash160(&rec.bond_pub_key.0))
}

/// `UnderwaterAt`: `ceil(mintedCents x CLAIM_THRESHOLD_BPS x COIN / collateralZat)`, `None`
/// without debt or when it exceeds `i64`.
fn underwater_at(v: &VaultRecord, p: &Params) -> Option<i64> {
    if v.minted_cents <= 0 || v.collateral_zat <= 0 {
        return None;
    }
    let rhs = u128::try_from(v.minted_cents)
        .ok()?
        .checked_mul(u128::try_from(p.claim_threshold_bps).ok()?)?
        .checked_mul(u128::try_from(COIN).ok()?)?;
    let c = u128::try_from(v.collateral_zat).ok()?;
    i64::try_from(rhs.checked_add(c - 1)? / c).ok()
}

/// `DecimalString`: a 256-bit value in decimal.
fn decimal(v: U256) -> String {
    if v.is_zero() {
        return "0".to_owned();
    }
    let ten = U256::from_u64(10);
    let mut digits = Vec::new();
    let mut v = v;
    while !v.is_zero() {
        let Some((q, r)) = v.checked_div_rem(ten) else {
            break;
        };
        // r < 10, so the digit is one ASCII byte
        digits.push(char::from(
            b'0'.saturating_add(u8::try_from(r.low_u64()).unwrap_or(0)),
        ));
        v = q;
    }
    digits.iter().rev().collect()
}

impl YedIndexView for LiveIndex {
    fn tip(&self) -> Option<IndexTip> {
        self.snap.index_tip().map(|t| IndexTip {
            height: i64::from(t.height),
            hash: t.block_hash,
        })
    }

    fn health(&self) -> Health {
        let reason = zakura_state::yed::yed_unhealthy_reason();
        Health {
            healthy: reason.is_none(),
            unhealthy_reason: reason.unwrap_or_default(),
            // kogany never rebuilds in place: a foreign index stops the node (U-21).
            rebuilt: false,
        }
    }

    fn state_hash(&self) -> Hash32 {
        self.snap.state_hash_internal()
    }

    fn totals(&self) -> Totals {
        let t = self.snap.totals();
        Totals {
            supply_cents: t.supply_cents,
            collateral_zat: t.collateral_zat,
            active_vaults: i64::from(t.active_vaults),
            void_vaults: i64::from(t.void_vaults),
            closed_vaults: i64::from(t.closed_vaults),
            claimed_vaults: i64::from(t.claimed_vaults),
            unbacked_cents: t.unbacked_cents,
            open_debt_cents: t.open_debt_cents,
        }
    }

    /// `AuditIndexRecords` (ycash6 `src/yellowback/index.cpp`). The signer sets' `lockedValue`
    /// audit reads the vault database, which this view does not hold: `sets` is empty.
    fn verify(&self) -> IndexAudit {
        let stored = self.totals();
        let mut derived = Totals::default();
        let mut mismatches = Vec::new();
        let mut tokens = 0i64;
        for (out, tok) in self.read().tokens() {
            tokens = tokens.saturating_add(1);
            if tok.cents <= 0 {
                mismatches.push(format!(
                    "Tokens: {}:{} holds {} cents",
                    display_hex(&out.txid),
                    out.n,
                    tok.cents
                ));
            } else {
                derived.supply_cents = derived.supply_cents.saturating_add(tok.cents);
            }
        }
        let mut vaults = 0i64;
        for (_, v) in self.read().vaults() {
            vaults = vaults.saturating_add(1);
            match v.status {
                RecordVaultStatus::Active => {
                    derived.collateral_zat =
                        derived.collateral_zat.saturating_add(v.collateral_zat);
                    derived.open_debt_cents =
                        derived.open_debt_cents.saturating_add(v.minted_cents);
                    derived.active_vaults = derived.active_vaults.saturating_add(1);
                }
                RecordVaultStatus::Claiming => {
                    derived.collateral_zat =
                        derived.collateral_zat.saturating_add(v.collateral_zat);
                    derived.open_debt_cents =
                        derived.open_debt_cents.saturating_add(v.minted_cents);
                }
                RecordVaultStatus::Voided => {
                    derived.void_vaults = derived.void_vaults.saturating_add(1)
                }
                RecordVaultStatus::Closed => {
                    derived.closed_vaults = derived.closed_vaults.saturating_add(1)
                }
                RecordVaultStatus::Claimed => {
                    derived.claimed_vaults = derived.claimed_vaults.saturating_add(1)
                }
            }
        }
        let fields = [
            ("supplyCents", stored.supply_cents, derived.supply_cents),
            (
                "collateralZat",
                stored.collateral_zat,
                derived.collateral_zat,
            ),
            ("activeVaults", stored.active_vaults, derived.active_vaults),
            ("voidVaults", stored.void_vaults, derived.void_vaults),
            ("closedVaults", stored.closed_vaults, derived.closed_vaults),
            (
                "claimedVaults",
                stored.claimed_vaults,
                derived.claimed_vaults,
            ),
            (
                "unbackedCents",
                stored.unbacked_cents,
                derived.unbacked_cents,
            ),
            (
                "openDebtCents",
                stored.open_debt_cents,
                derived.open_debt_cents,
            ),
        ];
        for (field, s, d) in fields {
            if s != d {
                mismatches.push(format!("Totals.{field}: stored {s}, records {d}"));
            }
        }
        if stored.supply_cents > stored.open_debt_cents {
            mismatches.push(format!(
                "Totals: supplyCents {} exceeds openDebtCents {}",
                stored.supply_cents, stored.open_debt_cents
            ));
        }
        if let Some(tip) = self.snap.index_tip() {
            let h = i64::from(tip.height);
            match self.stored_snapshot(h) {
                None => mismatches.push(format!("Snapshots: no snapshot at the tip height {h}")),
                Some(s) => {
                    if s.block_hash != tip.block_hash {
                        mismatches.push(format!(
                            "Snapshots[{h}].blockHash: {}, tip {}",
                            display_hex(&s.block_hash),
                            display_hex(&tip.block_hash)
                        ));
                    }
                    for (field, a, b) in [
                        ("supplyCents", s.supply_cents, stored.supply_cents),
                        ("collateralZat", s.collateral_zat, stored.collateral_zat),
                        ("openDebtCents", s.open_debt_cents, stored.open_debt_cents),
                    ] {
                        if a != b {
                            mismatches.push(format!(
                                "Snapshots[{h}].{field} (tip snapshot): {a}, Totals {b}"
                            ));
                        }
                    }
                }
            }
        }
        IndexAudit {
            ok: mismatches.is_empty(),
            tokens,
            vaults,
            stored,
            records: derived,
            sets: Vec::new(),
            mismatches,
            rules_version: 1,
        }
    }

    fn snapshot_at(&self, height: i64) -> Option<SnapshotView> {
        let s = self.stored_snapshot(height)?;
        Some(SnapshotView {
            block_hash: s.block_hash,
            tagged: s.tagged,
            quote: s.quote,
            p_fast: price(s.p_fast),
            p_mid: price(s.p_mid),
            p_slow: price(s.p_slow),
            p_mint: price(s.p_mint),
            p_claim: price(s.p_claim),
            sigma_mult_bps: i64::from(s.sigma_mult_bps),
            issued_zat: s.issued_zat,
            supply_cents: s.supply_cents,
            collateral_zat: s.collateral_zat,
            open_debt_cents: s.open_debt_cents,
            global_ratio_bps: price(s.global_ratio_bps),
            halt_mask: s.halt_mask,
            attest: attest_state(s.attest),
            seated: s.seated.clone(),
            pinned_keys: s.pinned_keys.clone(),
            pinned_seqs: s.pinned_seqs.clone(),
        })
    }

    fn quote_tags_in(&self, height: i64, window: i64) -> i64 {
        let lo = height
            .saturating_sub(window)
            .saturating_add(1)
            .max(i64::from(self.params.start_height));
        (lo..=height)
            .filter(|h| {
                u32::try_from(*h)
                    .ok()
                    .and_then(|h| self.snap.tag(h))
                    .is_some_and(|t| t.price_micro_usd != 0)
            })
            .count()
            .try_into()
            .unwrap_or(i64::MAX)
    }

    fn mint_gate(&self) -> MintGate {
        let halted = self
            .tip()
            .and_then(|t| self.stored_snapshot(t.height))
            .is_some_and(|s| s.halt_mask != 0);
        MintGate {
            supply_cap_cents: None,
            supply_cap_reached: false,
            minting_allowed: !halted,
            mintable_classes: if halted { Vec::new() } else { vec![0, 1, 2] },
        }
    }

    fn attest_info(&self) -> AttestInfo {
        let tip = self.tip_height();
        let snap = self.tip().and_then(|t| self.stored_snapshot(t.height));
        let state = snap
            .as_ref()
            .map_or(AttestState::UNARMED, |s| attest_state(s.attest));
        let r = tip.saturating_sub(self.ref_lag);
        let pool_fresh = snap.as_ref().map_or(0, |s| {
            s.seated
                .iter()
                .filter(|seq| self.pool_fresh_at(**seq, r))
                .count()
        });
        AttestInfo {
            state,
            seated_count: snap
                .as_ref()
                .map_or(0, |s| i64::try_from(s.seated.len()).unwrap_or(i64::MAX)),
            pool_size: i64::try_from(self.pool().size()).unwrap_or(i64::MAX),
            pool_fresh: i64::try_from(pool_fresh).unwrap_or(i64::MAX),
            armed: self.params.attest_required && state.status == AttestStatus::Armed,
            bond_min_zat: kogany_yellowback::math::bond_min_from_collateral_zat(
                self.snap.totals().collateral_zat,
                &self.params,
            ),
        }
    }

    /// `yed_listminers`'s rows (the RPC layer has checked the range).
    fn miners(&self, height: i64, window: i64) -> Vec<MinerRow> {
        let p = &self.params;
        let r = self.read();
        let policy = StatePayeePolicy::defaults(p);
        struct Acc {
            last_tag_height: i64,
            last_quote: i64,
            quote_tags: i64,
        }
        let mut rows: std::collections::BTreeMap<[u8; 20], Acc> = Default::default();
        let mut total = 0i64;
        let lo = height
            .saturating_sub(window)
            .saturating_add(1)
            .max(i64::from(p.start_height));
        for t in lo..=height {
            let Some(tag) = u32::try_from(t).ok().and_then(|t| r.tag(t)) else {
                continue;
            };
            if !tag.is_quote() {
                continue;
            }
            total = total.saturating_add(1);
            let row = rows.entry(tag.payout_key).or_insert(Acc {
                last_tag_height: t,
                last_quote: 0,
                quote_tags: 0,
            });
            row.last_tag_height = t;
            row.last_quote = i64::try_from(tag.price_micro_usd).unwrap_or(i64::MAX);
            row.quote_tags = row.quote_tags.saturating_add(1);
        }
        let eligible = eligible_payees(r, p, height);
        let mut order: Vec<(i64, [u8; 20])> =
            rows.iter().map(|(k, a)| (a.last_tag_height, *k)).collect();
        order.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let peer_lag = i64::from(p.peer_lag);
        let penalty = i64::from(policy.penalty_blocks);
        order
            .into_iter()
            .filter_map(|(_, key)| {
                let a = rows.get(&key)?;
                let mut until = 0;
                if penalized(r, p, &key, height, policy.penalty_blocks) {
                    let stop = height
                        .saturating_sub(peer_lag)
                        .saturating_sub(penalty)
                        .max(i64::from(p.start_height));
                    let mut t = height.saturating_sub(peer_lag).saturating_sub(1);
                    while t >= stop {
                        let quote_of_key = u32::try_from(t)
                            .ok()
                            .and_then(|h| r.tag(h))
                            .is_some_and(|tag| tag.is_quote() && tag.payout_key == key);
                        if quote_of_key
                            && u32::try_from(t)
                                .ok()
                                .and_then(|h| r.judgement(h))
                                .is_some_and(|j| j.penalized)
                        {
                            until = t.saturating_add(peer_lag).saturating_add(penalty);
                            break;
                        }
                        t = t.saturating_sub(1);
                    }
                }
                let (mut quoted, mut in_band) = (0i64, 0i64);
                let hi = height.saturating_sub(peer_lag);
                let lo = hi
                    .saturating_sub(i64::from(policy.accuracy_window.max(0)))
                    .saturating_add(1)
                    .max(i64::from(p.start_height));
                for t in lo..=hi {
                    let Some(h) = u32::try_from(t).ok() else {
                        continue;
                    };
                    if !r
                        .tag(h)
                        .is_some_and(|tag| tag.is_quote() && tag.payout_key == key)
                    {
                        continue;
                    }
                    let Some(j) = r.judgement(h).filter(|j| j.evaluated) else {
                        continue;
                    };
                    quoted = quoted.saturating_add(1);
                    if j.in_band {
                        in_band = in_band.saturating_add(1);
                    }
                }
                Some(MinerRow {
                    payout_key: key,
                    last_tag_height: a.last_tag_height,
                    last_quote: a.last_quote,
                    quote_tags: a.quote_tags,
                    share: if total > 0 {
                        a.quote_tags.saturating_mul(10_000) / total
                    } else {
                        0
                    },
                    registered: registered(r, p, &key, height),
                    eligible: eligible.contains(&key),
                    penalized_until: until,
                    accuracy_bps: (quoted > 0).then(|| in_band.saturating_mul(10_000) / quoted),
                    quoted,
                    in_band,
                })
            })
            .collect()
    }

    fn eligible_payees(&self, ref_height: i64) -> Vec<[u8; 20]> {
        eligible_payees(self.read(), &self.params, ref_height)
    }

    /// The FEE-W choice and its weight `10^4 + tiltBps x accuracyBps / 10^4`.
    fn default_payee(&self, ref_height: i64, selector: &[u8]) -> Option<([u8; 20], i64)> {
        let p = &self.params;
        let policy = StatePayeePolicy::defaults(p);
        let key = default_payee(self.read(), p, ref_height, selector, &policy)?;
        let acc = kogany_yellowback::state::accuracy_bps(
            self.read(),
            p,
            &key,
            ref_height,
            policy.accuracy_window,
        );
        Some((
            key,
            10_000i64
                .saturating_add(i64::from(policy.tilt_bps).saturating_mul(i64::from(acc)) / 10_000),
        ))
    }

    fn vault(&self, txid: &Hash32) -> Option<VaultRow> {
        let out = OutPoint { txid: *txid, n: 0 };
        let v = self.read().vault(&out)?;
        let tip_snap = self
            .tip()
            .is_some_and(|t| self.stored_snapshot(t.height).is_some());
        Some(self.vault_row(&out, &v, tip_snap))
    }

    fn vaults(&self, status: Option<VaultStatus>, count: usize, skip: usize) -> Vec<VaultRow> {
        let tip_snap = self
            .tip()
            .is_some_and(|t| self.stored_snapshot(t.height).is_some());
        self.read()
            .vaults()
            .into_iter()
            .filter(|(_, v)| status.is_none_or(|s| vault_status(v.status) == s))
            .skip(skip)
            .take(count)
            .map(|(out, v)| self.vault_row(&out, &v, tip_snap))
            .collect()
    }

    fn tokens(
        &self,
        holders: &[Holder],
        min_height: i64,
        count: usize,
        skip: usize,
    ) -> Vec<TokenRow> {
        let mut rows: Vec<TokenRow> = self
            .read()
            .tokens()
            .into_iter()
            .filter_map(|(out, t)| {
                let holder = holder_key(&t.script_pub_key)?;
                (holders.contains(&holder) && i64::from(t.height) >= min_height).then_some(
                    TokenRow {
                        outpoint: out,
                        cents: t.cents,
                        value_zat: t.n_value,
                        height: i64::from(t.height),
                        holder,
                    },
                )
            })
            .collect();
        rows.sort_by(|a, b| {
            a.height
                .cmp(&b.height)
                .then(a.outpoint.txid.0.cmp(&b.outpoint.txid.0))
                .then(a.outpoint.n.cmp(&b.outpoint.n))
        });
        rows.into_iter().skip(skip).take(count).collect()
    }

    fn claimable(&self, count: usize, skip: usize) -> Vec<ClaimableRow> {
        let p = &self.params;
        let tip = self.tip_height();
        if tip < 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut seen = 0usize;
        for (vault, v) in self.read().vaults() {
            if v.status != RecordVaultStatus::Active || tip < i64::from(v.app_height) {
                continue;
            }
            if out.len() >= count {
                break;
            }
            let est = self.estimate_claim(&vault, &v, tip);
            let claimable = est.claimable && est.p_claim.is_some();
            seen = seen.saturating_add(1);
            if seen <= skip {
                continue;
            }
            out.push(ClaimableRow {
                vault,
                owner: v.owner(),
                collateral_zat: v.collateral_zat,
                minted_cents: v.minted_cents,
                p_mint: v.p_mint,
                fee_zat: protocol_fee_zat(v.minted_cents, v.p_mint, p).unwrap_or(MAX_MONEY),
                claim_height: i64::from(v.claim_height),
                lock_height: i64::from(v.lock_height),
                claimable,
                underwater_at: underwater_at(&v, p),
                p_claim: est.p_claim,
                claim_path: if claimable { est.claim_path } else { "" },
                cancel_count: i64::from(v.cancel_count),
                cancels_required: cancels_required(&v, p, tip.saturating_add(1)),
                cancel_quiet_until: (v.last_cancel_height > 0).then(|| {
                    i64::from(v.last_cancel_height).saturating_add(i64::from(p.cancel_quiet))
                }),
                notice: self.notice_fields(&vault, &v),
                residual_zat: est.residual_zat,
                attest_fee_zat: est.attest_fee_zat,
            });
        }
        out
    }

    fn tx_info(&self, txid: &Hash32) -> Option<TxInfoRow> {
        self.tx_info_with(txid, None)
    }

    fn tx_info_with(&self, txid: &Hash32, tx: Option<&VaultTx>) -> Option<TxInfoRow> {
        let l = self.read().txlog(txid)?;
        Some(self.tx_info_row(txid, &l, tx))
    }

    fn estimate_collateral(
        &self,
        cents: i64,
        lock_blocks: i64,
        price_override: Option<i64>,
    ) -> Result<CollateralEstimate, YedError> {
        let p = &self.params;
        let r = self.read();
        let term_class = p.class_for_lock_blocks(lock_blocks).ok_or_else(|| {
            YedError::new(
                YedErrorKind::InvalidParameter,
                "mint-bad-lock",
                format!("lockBlocks {lock_blocks} is in no term class"),
            )
        })?;
        if cents < p.min_mint || cents > p.max_mint {
            return Err(YedError::plain(
                YedErrorKind::InvalidParameter,
                format!("cents must be between {} and {}", p.min_mint, p.max_mint),
            ));
        }
        let ref_h = self.tip_height().saturating_sub(self.ref_lag);
        let lock_height = ref_h.saturating_add(lock_blocks);
        if lock_height.saturating_add(i64::from(p.grace)) >= i64::from(LOCKTIME_THRESHOLD) {
            return Err(YedError::new(
                YedErrorKind::InvalidParameter,
                "mint-bad-lock",
                "lockHeight + GRACE exceeds LOCKTIME_THRESHOLD",
            ));
        }
        let snap = kogany_yellowback::state::snapshot_at(r, p, ref_h);
        let sigma = snap
            .as_ref()
            .map_or(p.sigma_mult_max_bps, |s| s.sigma_mult_bps);
        let armed = snap
            .as_ref()
            .is_some_and(|s| p.is_armed(s.attest.is_armed()));
        let x_mint = snap.as_ref().and_then(Snapshot::pmint);
        let (mut source, mut bundle_seqs, mut a_mint, mut divergence_bps) =
            ("", Vec::new(), None, None);
        let p_mint = match price_override {
            Some(v) => Some(v),
            None if armed => {
                let built = self.build_bundle_info(ref_h, &[]);
                let Some(a) = built.a_mint.filter(|_| built.sufficient) else {
                    return Err(built.insufficient());
                };
                a_mint = Some(a);
                bundle_seqs = built.seqs;
                match x_mint {
                    Some(x) => {
                        let fast = snap.as_ref().and_then(Snapshot::pfast).unwrap_or(x);
                        let diff = u128::from(fast.abs_diff(a));
                        let lo = u128::try_from(fast.min(a).max(1)).unwrap_or(1);
                        let d = diff.saturating_mul(10_000) / lo;
                        divergence_bps = Some(i64::try_from(d).unwrap_or(i64::MAX));
                        let limit = u128::try_from(p.diverge_bps_attest.max(0)).unwrap_or(0);
                        if diff.saturating_mul(10_000) > limit.saturating_mul(lo) {
                            return Err(YedError::new(
                                YedErrorKind::Rejected,
                                "mint10-diverged",
                                format!(
                                    "pFast {fast} and aMint {a} differ by {} bps (DIVERGE_BPS_ATTEST {})",
                                    divergence_bps.unwrap_or(i64::MAX),
                                    p.diverge_bps_attest
                                ),
                            ));
                        }
                        let m = x.min(a);
                        source = if m == a && a < x { "a" } else { "x" };
                        Some(m)
                    }
                    None => None,
                }
            }
            None => x_mint,
        };
        let base = p.base_ratio_bps.get(term_class).copied().unwrap_or(0);
        let min_ratio = min_ratio_bps(base, sigma);
        let (mut required, mut fee_cents, mut fee_zat, mut attest_fee) = (None, 0, 0, 0);
        if let Some(pm) = p_mint {
            let req = required_collateral_rounded(
                cents,
                min_ratio,
                pm,
                DEFAULT_COLLATERAL_GRANULARITY,
            )
            .ok_or_else(|| {
                YedError::new(
                    YedErrorKind::Rejected,
                    "mint-unsatisfiable",
                    "the required collateral exceeds MAX_MONEY (more YEC than can exist; lower the amount or the term class)",
                )
            })?;
            required = Some(req);
            fee_zat = protocol_fee_zat(cents, pm, p).unwrap_or(MAX_MONEY);
            fee_cents = protocol_fee_cents(cents, p);
            if !bundle_seqs.is_empty() {
                attest_fee = attest_fee_zat(fee_zat, p.attest_fee_bps);
            }
        }
        Ok(CollateralEstimate {
            required_zat: required,
            required_zat_floored: required,
            protocol_fee_cents: fee_cents,
            protocol_fee_zat: fee_zat,
            term_class: u8::try_from(term_class).unwrap_or(u8::MAX),
            lock_height,
            claim_height: lock_height.saturating_add(i64::from(p.grace)),
            min_ratio_bps: i64::from(min_ratio),
            base_ratio_bps: i64::from(base),
            sigma_mult_bps: i64::from(sigma),
            p_mint,
            ref_height: ref_h,
            x_mint,
            a_mint,
            source,
            armed,
            bundle_seqs,
            attest_fee_zat: attest_fee,
            divergence_bps,
            mint_blocked: self.mint_policy_refusal(ref_h, term_class, cents),
        })
    }

    fn attestors(&self, height: i64) -> Vec<AttestorRow> {
        let p = &self.params;
        let r = self.read();
        let snap = if height >= i64::from(p.start_height) {
            self.stored_snapshot(height)
        } else {
            None
        };
        let attest = snap.as_ref().map(|s| s.attest).unwrap_or_default();
        let mut last_bundle: std::collections::BTreeMap<u16, i64> = Default::default();
        for (k, v) in r.scan(Table::BundleLog) {
            if let (YedKey::BundleLog(h), YedRecord::BundleLog(row)) = (k, v) {
                for seq in row.seqs {
                    let e = last_bundle.entry(seq).or_insert(0);
                    *e = (*e).max(i64::from(h));
                }
            }
        }
        let fresh_ref = height.saturating_sub(self.ref_lag);
        attestors_of(r)
            .into_iter()
            .map(|(seq, rec)| {
                let origin = age_origin(&rec, &attest, p);
                AttestorRow {
                    seq,
                    attestor_pub_key: rec.attestor_pub_key,
                    bond_pub_key: rec.bond_pub_key,
                    bond_outpoint: rec.bond_outpoint,
                    bond_zat: rec.bond_zat,
                    bond_locktime: rec.bond_locktime,
                    flags: rec.flags,
                    register_height: i64::from(rec.register_height),
                    status: attestor_status(rec.status),
                    status_height: i64::from(rec.status_height),
                    bond_spent_height: (rec.bond_spent_height != 0)
                        .then_some(i64::from(rec.bond_spent_height)),
                    seated_since: (rec.seated_since != 0).then_some(i64::from(rec.seated_since)),
                    last_act: i64::from(rec.last_act),
                    bond_frozen: rec.bond_frozen,
                    founding: attest.status != RecordStatus::Unarmed
                        && origin == i64::from(attest.trigger_height),
                    weight: decimal(attestor_weight(&rec, &attest, p, height)),
                    seat_weight: decimal(seat_weight(
                        rec.bond_zat,
                        height.saturating_sub(origin),
                        i64::from(p.seat_age_unit),
                        i64::from(p.seat_age_cap),
                    )),
                    evicted: rec.flags & ATTESTOR_FLAG_EVICTED != 0,
                    seated: snap.as_ref().is_some_and(|s| s.seated.contains(&seq)),
                    pinned: snap.as_ref().is_some_and(|s| s.pinned_seqs.contains(&seq)),
                    last_bundle_height: last_bundle.get(&seq).copied(),
                    pool_fresh: self.pool_fresh_at(seq, fresh_ref),
                }
            })
            .collect()
    }

    fn pool(&self) -> Vec<PooledAttestation> {
        let p = &self.params;
        let tip = self.tip_height();
        let seated = self
            .tip()
            .and_then(|t| self.stored_snapshot(t.height))
            .map(|s| s.seated)
            .unwrap_or_default();
        let floor = tip
            .saturating_sub(self.ref_lag)
            .saturating_sub(i64::from(p.attest_max_age));
        self.pool()
            .all()
            .into_iter()
            .map(|x| PooledAttestation {
                attestation: x.attestation,
                received_height: x.received_height,
                seated: seated.contains(&x.attestation.seq),
                fresh: i64::from(x.attestation.cited_height) > floor,
            })
            .collect()
    }

    fn build_bundle(&self, ref_height: i64, selector: &[u8]) -> Result<BuiltBundle, YedError> {
        let b = self.build_bundle_info(ref_height, selector);
        if !b.sufficient {
            return Err(b.insufficient());
        }
        Ok(BuiltBundle {
            armed: b.armed,
            selected: b.selected,
            seqs: b.seqs,
            missing: b.missing,
            bundle: encode_bundle(&Bundle::of(b.atts)),
            a_mint: b.a_mint,
            a_claim: b.a_claim,
        })
    }

    fn selection(&self, ref_height: i64, selector: &[u8]) -> Selection {
        let p = &self.params;
        let r = self.read();
        let snap = self.stored_snapshot(ref_height);
        let attest = snap.as_ref().map(|s| s.attest).unwrap_or_default();
        let weight_of =
            |seq: u16| attestor_of(r, seq).map(|rec| attestor_weight(&rec, &attest, p, ref_height));
        let mut pool = Vec::new();
        let mut sum = U256::ZERO;
        if let Some(s) = &snap {
            for seq in &s.seated {
                if s.pinned_seqs.contains(seq) {
                    continue;
                }
                pool.push(*seq);
                if let Some(w) = weight_of(*seq) {
                    sum = sum.wrapping_add(w);
                }
            }
        }
        let b = self.build_bundle_info(ref_height, selector);
        let selected = b
            .selected
            .iter()
            .map(|seq| {
                let rec = attestor_of(r, *seq);
                SelectedAttestor {
                    seq: *seq,
                    weight: decimal(weight_of(*seq).unwrap_or(U256::ZERO)),
                    bond_key: rec.as_ref().and_then(bond_key_hash),
                    status: rec.as_ref().map(|r| attestor_status(r.status)),
                    pool_fresh: b.seqs.contains(seq),
                }
            })
            .collect();
        Selection {
            armed: armed_at(r, p, ref_height),
            pool,
            sum_weight: decimal(sum),
            selected,
        }
    }

    fn notice(&self, txid: &Hash32) -> NoticeLookup {
        let out = OutPoint { txid: *txid, n: 0 };
        if self.read().vault(&out).is_none() {
            return NoticeLookup::VaultNotFound;
        }
        match self.read().notice(&out) {
            None => NoticeLookup::None,
            Some(NoticeRecord {
                height,
                ref_height,
                p_emerg,
            }) => NoticeLookup::Standing(NoticeRow {
                txid: Hash32::ZERO,
                height: i64::from(height),
                ref_height: i64::from(ref_height),
                p_emerg,
            }),
        }
    }
}

/// A txid in display (reversed) hex.
fn display_hex(h: &Hash32) -> String {
    kogany_yellowback::state::display_hex(h)
}
