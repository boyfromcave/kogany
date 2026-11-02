//! Tests of the Ycash mining hooks (kogany W8): the coinbase tag against ycash6's bytes
//! (`testdata/yellowback/yellowback_golden.json`, `src/test/yellowback_tag_tests.cpp`), the
//! template fields, the policy sigops (`src/test/pq_script_tests.cpp` `pq_sigops`) and the template
//! filter on a scripted mempool.

use std::{collections::HashSet, sync::Arc};

use kogany_vault::{
    act::{
        act_msg, encode_act, encode_payload, public_key, sign_recoverable, Act, ActBody,
        SetCreateBody, SetJoinBody, SET_FLAG_OPEN,
    },
    state::{MemberStatus, Rules, SetRecord, SetState, StateRead},
    template::bond_script_pubkey,
    Hash32, PubKeyBytes,
};
use kogany_yellowback::codecs::tag::{encode_tag, find_tag, height_prefix, tag_push, CoinbaseTag};
use zcash_transparent::{address::TransparentAddress, coinbase::MAX_COINBASE_SCRIPT_LEN};

use zakura_chain::{
    amount::{Amount, NonNegative},
    block::Height,
    parameters::Network,
    serialization::ZcashDeserializeInto,
    transaction::{self, LockTime, Transaction, UnminedTx, VerifiedUnminedTx},
    transparent::{self, Output, Script},
};
use zakura_node_services::mempool::TransactionDependencies;

use super::*;
use crate::{
    config::mining::{ZAKURA_COINBASE_MARKER, ZAKURA_COINBASE_SEPARATOR},
    methods::types::{
        get_block_template::{
            coinbase_data, zip317::select_mempool_transactions_filtered, MinerAddress, MinerParams,
        },
        transaction::TransactionTemplate,
    },
};

// ---- helpers ----------------------------------------------------------------------------

fn golden() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/yellowback/yellowback_golden.json"
    );
    let text = std::fs::read_to_string(path).expect("the pinned golden vector is in the tree");
    serde_json::from_str(&text).expect("the pinned golden vector is JSON")
}

fn miner_params(data: Option<&[u8]>, yellowback: Option<YellowbackMiner>) -> MinerParams {
    MinerParams {
        addr: MinerAddress::from(TransparentAddress::PublicKeyHash([0x7e; 20])),
        data: data.map(|d| {
            zcash_script::pv::push_value(&coinbase_data(d)).expect("the test data fits a push")
        }),
        memo: None,
        yellowback,
        block_unpaid_action_limit: u32::MAX,
    }
}

fn miner_with(tag: CoinbaseTag) -> YellowbackMiner {
    YellowbackMiner {
        tag: Some(tag),
        payout_key: Some(tag.payout_key),
        quote_age_seconds: Some(0),
        registered: false,
        eligible: false,
    }
}

/// The input script of a serialized v4 coinbase, read byte by byte (the golden vector's
/// synthetic coinbases need not satisfy Zakura's parser: some carry a one-byte script).
fn raw_coinbase_script(tx: &[u8]) -> Vec<u8> {
    // header 4, version group 4, one input (count 1), null prevout 36, then the script length.
    assert_eq!(tx[8], 1, "one coinbase input");
    let len = usize::from(tx[45]);
    assert!(len < 0xfd, "a coinbase script fits a one-byte length");
    tx[46..46 + len].to_vec()
}

fn coinbase_script(template: &TransactionTemplate<NegativeOrZero>) -> Vec<u8> {
    coinbase_script_sig(template).expect("a coinbase template has a coinbase script")
}

/// ycash6 `yellowback_tag_tests.cpp` `QuoteTag()`: flags 1, $0.05, mask 7, key `ab…ab`.
fn cxx_quote_tag(price: u64) -> CoinbaseTag {
    CoinbaseTag {
        flags: 0x01,
        price_micro_usd: price,
        source_mask: 7,
        payout_key: [0xab; 20],
    }
}

fn coinbase(
    network: &Network,
    height: u32,
    params: &MinerParams,
) -> TransactionTemplate<NegativeOrZero> {
    TransactionTemplate::new_coinbase(network, Height(height), params, Amount::zero(), None)
        .expect("the test coinbase builds")
}

// ---- the coinbase tag ---------------------------------------------------------------------

/// Every tagged coinbase of the golden vector: the tag kogany appends for the same tag fields is
/// the bytes ycash6 wrote, it reads back the same, and `coinbaseaux.flags` is exactly those bytes.
#[test]
fn tag_bytes_equal_ycash6_for_the_golden_coinbases() {
    let regtest = Network::new_regtest(Default::default());
    let g = golden();
    let mut tagged = 0;
    for block in g["blocks"].as_array().expect("blocks") {
        let height = u32::try_from(block["height"].as_u64().expect("height")).expect("u32");
        let data = hex::decode(block["txs"][0].as_str().expect("coinbase hex")).expect("hex");
        let script = raw_coinbase_script(&data);
        let h = i32::try_from(height).expect("i32");
        let Some(tag) = find_tag(&script, h) else {
            continue;
        };
        tagged += 1;

        // ycash6's bytes: the direct push 0x24 ‖ 36 bytes, found after the height prefix.
        let push = tag_push(&tag);
        assert_eq!(push.len(), 37);
        assert_eq!(push[0], 0x24);
        assert_eq!(&push[1..], &encode_tag(&tag)[..]);
        let after_height = &script[height_prefix(h).len()..];
        assert!(
            after_height
                .windows(push.len())
                .any(|w| w == push.as_slice()),
            "height {height}: ycash6's coinbase carries the tag push"
        );

        // kogany's coinbase for the same tag at the same height.
        let params = miner_params(Some(b""), Some(miner_with(tag)));
        let cb = coinbase(&regtest, height, &params);
        let kogany = coinbase_script(&cb);
        assert!(
            kogany.starts_with(&height_prefix(h)),
            "height {height}: BIP34 prefix"
        );
        assert_eq!(
            coinbase_flags_of(&kogany),
            push,
            "height {height}: coinbaseaux.flags"
        );
        assert_eq!(
            find_tag(&kogany, h),
            Some(tag),
            "height {height}: the tag reads back"
        );
        assert!(kogany.len() <= MAX_COINBASE_SCRIPT_LEN);

        let (aux, info) = template_fields(&regtest, Height(height), &kogany, &miner_with(tag));
        assert_eq!(aux.flags, hex::encode(&push));
        assert_eq!(info.tag, hex::encode(&push));
        assert_eq!(info.kind, if tag.is_quote() { "quote" } else { "signal" });
    }
    assert!(tagged > 0, "the golden vector carries tagged coinbases");
}

/// `tag1_encoding_is_36_bytes_one_direct_push`'s bytes, and the coinbase that carries them.
#[test]
fn tag_push_matches_the_cxx_encoding_vector() {
    let tag = cxx_quote_tag(50_000);
    let push = tag_push(&tag);
    assert_eq!(
        hex::encode(&push),
        concat!(
            "24",
            "59454421",
            "01",
            "01",
            "50c3000000000000",
            "0700",
            "abababababababababababababababababababab"
        )
    );
    let cb = coinbase(
        &Network::Mainnet,
        1_000_000,
        &miner_params(Some(b""), Some(miner_with(tag))),
    );
    let script = coinbase_script(&cb);
    // <height> <the Zakura marker push> <the tag push>
    let mut expected = height_prefix(1_000_000);
    expected.push(4);
    expected.extend_from_slice(ZAKURA_COINBASE_MARKER.as_bytes());
    expected.extend_from_slice(&push);
    assert_eq!(script, expected);
    assert_eq!(coinbase_flags_of(&script), push);
}

/// `tag1_byte_budget_at_every_height_push_width`: the tag fits after every height push width,
/// with the largest `extra_coinbase_data` (which then gives way to the marker alone).
#[test]
fn tag_fits_at_every_height_push_width() {
    let tag = cxx_quote_tag(50_000);
    let longest = vec![b'p'; crate::config::mining::MAX_USER_COINBASE_DATA_LEN];
    let regtest = Network::new_regtest(Default::default());
    for height in [1u32, 16, 17, 65_535, 16_777_215, 16_777_216] {
        let h = i32::try_from(height).expect("i32");
        for data in [&b""[..], &b"/pool/"[..], longest.as_slice()] {
            let cb = coinbase(
                &regtest,
                height,
                &miner_params(Some(data), Some(miner_with(tag))),
            );
            let script = coinbase_script(&cb);
            assert!(script.len() <= MAX_COINBASE_SCRIPT_LEN, "height {height}");
            assert_eq!(find_tag(&script, h), Some(tag), "height {height}");
            assert_eq!(
                coinbase_flags_of(&script),
                tag_push(&tag),
                "height {height}"
            );
            let marker_and_data = &script[height_prefix(h).len()..script.len() - 37];
            if data.len() < 10 {
                // The pool's data stays when it fits.
                let mut expected = coinbase_data(data);
                expected.insert(0, u8::try_from(expected.len()).expect("small"));
                assert_eq!(marker_and_data, expected.as_slice(), "height {height}");
            } else {
                assert_eq!(&marker_and_data[1..], ZAKURA_COINBASE_MARKER.as_bytes());
            }
        }
    }
    // Without a tag the coinbase is Zakura's own, byte for byte.
    let plain = coinbase(
        &Network::Mainnet,
        1_000_000,
        &miner_params(Some(b"/pool/"), None),
    );
    let none = coinbase(
        &Network::Mainnet,
        1_000_000,
        &miner_params(Some(b"/pool/"), Some(YellowbackMiner::default())),
    );
    assert_eq!(coinbase_script(&plain), coinbase_script(&none));
    assert!(coinbase_script(&plain)
        .windows(ZAKURA_COINBASE_SEPARATOR.len())
        .any(|w| w == ZAKURA_COINBASE_SEPARATOR.as_bytes()));
}

/// The txid and serialization of a tagged coinbase are its own, its fee and sigops unchanged.
#[test]
fn tagged_coinbase_is_consistent() {
    let net = Network::Mainnet;
    let plain = coinbase(&net, 1_000_000, &miner_params(Some(b""), None));
    let tagged = coinbase(
        &net,
        1_000_000,
        &miner_params(Some(b""), Some(miner_with(cxx_quote_tag(50_000)))),
    );
    let tx: Transaction = tagged
        .data
        .as_ref()
        .zcash_deserialize_into()
        .expect("decodes");
    assert_eq!(tx.hash(), tagged.hash);
    assert_ne!(tagged.hash, plain.hash);
    assert_eq!(tagged.fee, plain.fee);
    assert_eq!(tagged.sigops, plain.sigops);
    assert_eq!(tx.outputs(), {
        let p: Transaction = plain
            .data
            .as_ref()
            .zcash_deserialize_into()
            .expect("decodes");
        p.outputs().to_vec()
    });
}

/// `BuildTagScript`: a fresh quote and a payout key make a quote tag with no signal bit; a stale
/// quote, no key or a price outside TAG-2 make none.
#[test]
fn build_tag_follows_build_tag_script() {
    let key = Some([0x11; 20]);
    let tag = YellowbackMiner::build_tag(true, key, 2_000_000, 3).expect("a quote tag");
    assert_eq!(tag.flags, 0);
    assert_eq!(tag.price_micro_usd, 2_000_000);
    assert_eq!(tag.source_mask, 3);
    assert_eq!(tag.payout_key, [0x11; 20]);
    assert!(YellowbackMiner::build_tag(false, key, 2_000_000, 3).is_none());
    assert!(YellowbackMiner::build_tag(true, None, 2_000_000, 3).is_none());
    assert!(
        YellowbackMiner::build_tag(true, key, i64::from(u32::MAX) * 1_000_000_000, 3).is_none()
    );
    assert!(YellowbackMiner::build_tag(true, key, -1, 3).is_none());
    let miner = YellowbackMiner {
        tag: Some(tag),
        ..Default::default()
    };
    assert_eq!(miner.flags(), tag_push(&tag));
    assert!(YellowbackMiner::default().flags().is_empty());
}

/// `CoinbaseFlagsOf`: the bytes after the two leading operations.
#[test]
fn coinbase_flags_of_skips_two_operations() {
    let tag = tag_push(&cxx_quote_tag(50_000));
    // ycashd's own `<height> OP_0 <flags>`.
    let mut ycashd = height_prefix(1234);
    ycashd.push(0x00);
    ycashd.extend_from_slice(&tag);
    assert_eq!(coinbase_flags_of(&ycashd), tag);
    // IncrementExtraNonce's `<height> <extranonce>`.
    let mut extranonce = height_prefix(1234);
    extranonce.extend_from_slice(&[0x04, 1, 2, 3, 4]);
    extranonce.extend_from_slice(&tag);
    assert_eq!(coinbase_flags_of(&extranonce), tag);
    assert!(coinbase_flags_of(&height_prefix(1234)).is_empty());
    assert!(coinbase_flags_of(&[]).is_empty());
    // A truncated second push.
    let mut truncated = height_prefix(1234);
    truncated.extend_from_slice(&[0x05, 1, 2]);
    assert!(coinbase_flags_of(&truncated).is_empty());
}

/// `TemplateInfo`: the tag decoded from the coinbase, the node's miner status beside it.
#[test]
fn template_info_matches_ycashd_fields() {
    let net = Network::Mainnet;
    let tag = YellowbackMiner::build_tag(true, Some([0x22; 20]), 1_500_000, 1).expect("a tag");
    let miner = YellowbackMiner {
        tag: Some(tag),
        payout_key: Some([0x22; 20]),
        quote_age_seconds: Some(12),
        registered: true,
        eligible: false,
    };
    let cb = coinbase(
        &net,
        1_000_000,
        &miner_params(Some(b""), Some(miner.clone())),
    );
    let (aux, info) = template_fields(&net, Height(1_000_000), &coinbase_script(&cb), &miner);
    assert_eq!(aux.flags, hex::encode(tag_push(&tag)));
    let json = serde_json::to_value(&info).expect("serializes");
    assert_eq!(
        json,
        serde_json::json!({
            "tag": hex::encode(tag_push(&tag)),
            "kind": "quote",
            "priceMicroUsd": 1_500_000,
            "quoteAgeSeconds": 12,
            "payoutAddress": transparent::Address::from_pub_key_hash(net.kind(), [0x22; 20]).to_string(),
            "registered": true,
            "eligible": false,
            "healthy": true,
        })
    );
    // No tag: kind none, price 0, the node's payout key.
    let untagged = YellowbackMiner {
        tag: None,
        quote_age_seconds: None,
        ..miner
    };
    let cb = coinbase(
        &net,
        1_000_000,
        &miner_params(Some(b""), Some(untagged.clone())),
    );
    let (aux, info) = template_fields(&net, Height(1_000_000), &coinbase_script(&cb), &untagged);
    assert_eq!(aux.flags, "");
    assert_eq!(info.kind, "none");
    assert_eq!(info.price_micro_usd, 0);
    assert_eq!(info.quote_age_seconds, None);
    assert!(info.payout_address.is_some());
    // The unhealthy refusal is ycashd's.
    let error = unhealthy_error("storage failure in ConnectBlock");
    assert_eq!(error.code(), -26);
    assert_eq!(
        error.message(),
        "yellowback-unhealthy: storage failure in ConnectBlock; restart with -reindex-yellowback"
    );
}

// ---- sigops -----------------------------------------------------------------------------

const OP_CHECKPQSIG: u8 = 0xc2;

fn spend(script_sig: Vec<u8>, spent: Vec<u8>) -> VerifiedUnminedTx {
    verified(
        vec![input(0x02, 0, script_sig)],
        vec![Output::new(amount(1), Script::new(&[0x51]))],
        vec![Output::new(amount(1), Script::new(&spent))],
    )
}

/// `pq_sigops`: 20 per OP_CHECKPQSIG executed (scriptSig, spent script, P2SH redeem), none
/// inside pushes, none in a coinbase.
#[test]
fn pq_sigops_count_as_ycash6() {
    // A PQPKH-like spent script with one OP_CHECKPQSIG; pushes of 0xc2 bytes count nothing.
    let spk = vec![
        0x76,
        0xa9,
        0x14,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        0x88,
        OP_CHECKPQSIG,
    ];
    let pushes = vec![
        0x03,
        OP_CHECKPQSIG,
        OP_CHECKPQSIG,
        OP_CHECKPQSIG,
        0x01,
        OP_CHECKPQSIG,
    ];
    assert_eq!(pq_sigops(&spend(pushes.clone(), spk.clone())), 20);
    // P2SH of it: the redeem script, the scriptSig's last push, counts.
    let mut p2sh_sig = pushes.clone();
    p2sh_sig.push(u8::try_from(spk.len()).expect("small"));
    p2sh_sig.extend_from_slice(&spk);
    let p2sh = [&[0xa9u8, 0x14][..], &[0u8; 20][..], &[0x87u8][..]].concat();
    assert_eq!(pq_sigops(&spend(p2sh_sig.clone(), p2sh.clone())), 20);
    // Not push-only: the redeem script is not read.
    let mut not_push_only = p2sh_sig;
    not_push_only.insert(0, 0x76);
    assert_eq!(pq_sigops(&spend(not_push_only, p2sh)), 0);
    // In the scriptSig itself, and two in the spent script.
    assert_eq!(
        pq_sigops(&spend(vec![OP_CHECKPQSIG, OP_CHECKPQSIG], vec![0x51])),
        40
    );
    assert_eq!(pq_sigops(&spend(vec![0x51], vec![0x51])), 0);
    let mixed = vec![0xac, OP_CHECKPQSIG, 0xad, OP_CHECKPQSIG];
    assert_eq!(pq_sigops(&spend(vec![], mixed)), 40);
    // The template entry reports it on top of the legacy and P2SH count.
    let tx = spend(vec![OP_CHECKPQSIG], vec![0x51]);
    let template = TransactionTemplate::<NonNegative>::from(&tx);
    assert_eq!(template.sigops, tx.block_sigop_count() + 20);
}

// ---- the template filter ----------------------------------------------------------------

fn amount(zat: i64) -> Amount<NonNegative> {
    Amount::try_from(zat).expect("a valid amount")
}

fn input(seed: u8, index: u32, script_sig: Vec<u8>) -> transparent::Input {
    transparent::Input::PrevOut {
        outpoint: transparent::OutPoint {
            hash: transaction::Hash([seed; 32]),
            index,
        },
        unlock_script: Script::new(&script_sig),
        sequence: u32::MAX,
    }
}

fn verified(
    inputs: Vec<transparent::Input>,
    outputs: Vec<Output>,
    spent: Vec<Output>,
) -> VerifiedUnminedTx {
    let tx = Transaction::V4 {
        inputs,
        outputs,
        lock_time: LockTime::unlocked(),
        expiry_height: Height(0),
        joinsplit_data: None,
        sapling_shielded_data: None,
    };
    VerifiedUnminedTx::new(UnminedTx::from(tx), amount(100_000), 0, 0, Arc::new(spent))
        .expect("the test transaction pays the relay fee")
}

fn key(seed: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[0] = 0x33;
    secret[31] = seed;
    secret
}

fn pubkey(seed: u8) -> PubKeyBytes {
    public_key(&key(seed)).expect("a valid secret")
}

/// An open set (`vault_state_tests` `Params(true)`), created at height 100.
fn open_set() -> (SetState, Hash32) {
    let params = SetCreateBody {
        seats: 5,
        unlock_threshold: 2,
        cancel_threshold: 1,
        slash_threshold: 2,
        flags: SET_FLAG_OPEN,
        rate_limit_bps: 0,
        rate_window: 100,
        liveness_window: 50,
        bond_min: 1000,
        bond_lock_min: 10,
        maturity: 5,
        admit_key: pubkey(200),
    };
    let set_id = Hash32([0x5e; 32]);
    let mut state = SetState::new();
    state.sets.insert(set_id, SetRecord::new(params, 100));
    (state, set_id)
}

/// A `SET_JOIN` of the key `member` to `set_id`, funded by the outpoint `(funding, 0)`, with
/// its bond at output 0.
fn join(set_id: Hash32, member: u8, funding: u8) -> VerifiedUnminedTx {
    let body = SetJoinBody {
        set_id,
        member_key: pubkey(member),
        bond_locktime: 1101,
        bond_vout: 0,
    };
    let vin0 = kogany_vault::OutPoint {
        txid: Hash32([funding; 32]),
        n: 0,
    };
    let msg = act_msg(&encode_payload(&ActBody::Join(body)), &vin0);
    let sig = sign_recoverable(&key(member), &msg).expect("signs");
    let act = encode_act(&Act {
        body: ActBody::Join(body),
        sigs: vec![sig],
    });
    let bond = bond_script_pubkey(1101, &pubkey(member)).expect("a bond script");
    verified(
        vec![input(funding, 0, vec![])],
        vec![
            Output::new(amount(1000), Script::new(&bond)),
            Output::new(amount(0), Script::new(&act)),
        ],
        vec![Output::new(amount(1_000_000), Script::new(&[0x51]))],
    )
}

/// An ordinary payment, funded by `(funding, 0)`.
fn payment(funding: u8) -> VerifiedUnminedTx {
    verified(
        vec![input(funding, 0, vec![])],
        vec![Output::new(amount(5000), Script::new(&[0x51]))],
        vec![Output::new(amount(1_000_000), Script::new(&[0x51]))],
    )
}

fn rules() -> Rules<'static> {
    Rules::new(0, 0)
}

/// The TPL-1 analogue: of two acts that conflict (the same key joining the same set twice), a
/// template keeps the first it meets and skips the other; the kept one's effect is in the
/// running state; ordinary transactions pass.
#[test]
fn filter_keeps_the_first_of_two_conflicting_acts() {
    let (state, set_id) = open_set();
    let (a, b, pay) = (join(set_id, 1, 0x41), join(set_id, 1, 0x42), payment(0x43));
    let mut filter = TemplateFilter::new(Height(101), Some((state, rules())), None);
    assert!(filter.keep(&a));
    let member = filter
        .vault_state()
        .and_then(|s| s.member(&set_id, &pubkey(1)))
        .expect("the kept join's member");
    assert_eq!(member.status, MemberStatus::Active);
    assert!(
        !filter.keep(&b),
        "the second join of the same key conflicts"
    );
    assert!(filter.keep(&pay));
    // A different key joins.
    assert!(filter.keep(&join(set_id, 2, 0x44)));
    // A join to an unknown set is refused.
    assert!(!filter.keep(&join(Hash32([0x77; 32]), 3, 0x45)));
}

/// While Vault is active but its state is unavailable, no candidate that touches the
/// primitive enters a template; others do.
#[test]
fn filter_without_state_leaves_out_vault_transactions() {
    let (_, set_id) = open_set();
    let mut filter = TemplateFilter::unavailable(Height(101));
    assert!(!filter.keep(&join(set_id, 1, 0x41)));
    assert!(filter.keep(&payment(0x43)));
}

/// The YED half is asked after the vault half and can refuse; a refusal leaves the vault state
/// unchanged.
#[test]
fn filter_asks_the_yed_half_last() {
    struct RefuseSecond(usize);
    impl YedTemplateFilter for RefuseSecond {
        fn keep(&mut self, _: &VerifiedUnminedTx) -> bool {
            self.0 += 1;
            self.0 != 2
        }
    }
    let (state, set_id) = open_set();
    let mut filter = TemplateFilter::new(
        Height(101),
        Some((state, rules())),
        Some(Box::new(RefuseSecond(0))),
    );
    assert!(filter.keep(&payment(0x43)));
    assert!(
        !filter.keep(&join(set_id, 1, 0x41)),
        "the YED half refuses the second candidate"
    );
    assert!(filter
        .vault_state()
        .and_then(|s| s.member(&set_id, &pubkey(1)))
        .is_none());
    assert!(
        filter.keep(&join(set_id, 1, 0x42)),
        "then the same key can join"
    );
}

/// A scripted mempool through ZIP-317 selection: whatever the random order, no template carries
/// both conflicting acts, and every other candidate is selected.
#[test]
fn no_template_carries_two_conflicting_acts() {
    let network = Network::new_regtest(Default::default());
    let (state, set_id) = open_set();
    let mempool = vec![
        join(set_id, 1, 0x41),
        join(set_id, 1, 0x42),
        join(set_id, 2, 0x44),
        payment(0x43),
    ];
    let conflicting: HashSet<_> = mempool[..2]
        .iter()
        .map(|tx| tx.transaction.id().mined_id())
        .collect();
    let params = miner_params(None, None);
    let mut kept_first = HashSet::new();
    for _ in 0..64 {
        let filter = TemplateFilter::new(Height(101), Some((state.clone(), rules())), None);
        let selected = select_mempool_transactions_filtered(
            &network,
            Height(101),
            &params,
            None,
            mempool.clone(),
            TransactionDependencies::default(),
            Some(filter),
        )
        .expect("the template is built");
        let ids: Vec<_> = selected
            .iter()
            .map(|(_, tx)| tx.transaction.id().mined_id())
            .collect();
        assert_eq!(ids.len(), 3, "one of the two conflicting joins is left out");
        let kept: Vec<_> = ids.iter().filter(|id| conflicting.contains(id)).collect();
        assert_eq!(kept.len(), 1);
        kept_first.insert(*kept[0]);
    }
    // Without a filter (Vault inactive) all four are selected.
    let selected = select_mempool_transactions_filtered(
        &network,
        Height(101),
        &params,
        None,
        mempool,
        TransactionDependencies::default(),
        None,
    )
    .expect("the template is built");
    assert_eq!(selected.len(), 4);
    assert!(!kept_first.is_empty());
}

/// Hooks that serve one set state.
struct WithState(Arc<SetState>);

#[async_trait::async_trait]
impl YcashMining for WithState {
    async fn yellowback_miner(&self) -> Result<Option<YellowbackMiner>, String> {
        Ok(None)
    }
    async fn vault_state(&self, _: zakura_chain::block::Hash) -> Option<Arc<SetState>> {
        Some(self.0.clone())
    }
}

/// `prepare`: no vault filter before activation (ycashd builds no `TemplateRun` there), the
/// fail-closed filter without a state, the running one with the state and the network's rules
/// (ycash6 regtest's set maturity, 2).
#[tokio::test]
async fn prepare_follows_the_vault_activation() {
    use zakura_chain::parameters::testnet::{ConfiguredActivationHeights, RegtestParameters};

    let network = Network::new_regtest(RegtestParameters::from(ConfiguredActivationHeights {
        vault: Some(101),
        ..Default::default()
    }));
    let (state, set_id) = open_set();
    let parent = zakura_chain::block::Hash([0; 32]);
    let a = join(set_id, 1, 0x41);

    let mut before = TemplateFilter::prepare(&network, Height(100), parent, &NotLive).await;
    assert!(before.keep(&a), "no vault filter below activation");

    let mut no_state = TemplateFilter::prepare(&network, Height(101), parent, &NotLive).await;
    assert!(!no_state.keep(&a), "fail closed without a set state");
    assert!(no_state.keep(&payment(0x43)));

    // With the state, under the network's Vault parameters (`vault_network_params`).
    let hooks = WithState(Arc::new(state));
    let mut running = TemplateFilter::prepare(&network, Height(101), parent, &hooks).await;
    assert!(running.keep(&a));
    assert!(!running.keep(&join(set_id, 1, 0x42)));
}

/// S5 parity (`yellowback_stock_node.py`, `yellowback_mining.py`): a Ycash template carries
/// ycashd's key set, so neither Zakura's `maxtime` nor its `workid`; one read back from JSON
/// still parses (the internal `maxtime` is the latest time).
#[test]
fn ycash_template_has_no_maxtime_or_workid() {
    let json = include_str!("../../../../../tests/vectors/getblocktemplate_response_template.json");
    let parsed: crate::methods::types::get_block_template::GetBlockTemplateResponse =
        serde_json::from_str(json).expect("the vector parses");
    let out = serde_json::to_value(&parsed).expect("serializes");
    assert!(out.get("curtime").is_some() && out.get("mintime").is_some());
    assert!(out.get("maxtime").is_none(), "{out}");
    assert!(out.get("workid").is_none(), "{out}");
    let mut without: serde_json::Value = serde_json::from_str(json).expect("json");
    let object = without.as_object_mut().expect("an object");
    object.remove("maxtime");
    object.remove("workid");
    let back: crate::methods::types::get_block_template::GetBlockTemplateResponse =
        serde_json::from_value(without).expect("ycashd's key set parses");
    let crate::methods::types::get_block_template::GetBlockTemplateResponse::TemplateMode(t) = back
    else {
        panic!("a template");
    };
    assert_eq!(t.max_time(), zakura_chain::serialization::DateTime32::MAX);
}
