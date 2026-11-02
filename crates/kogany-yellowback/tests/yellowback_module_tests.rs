// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! ycash6 `src/test/vault_state_tests.cpp` `module_table_registers_yed` (P4, §15.7) over
//! [`kogany_yellowback::module::YedModule`] (plan W5-f), and the `LruSigCache` bounds.

use kogany_vault::state::{
    find_module, registered_modules, Module, ModuleContext, SetState, VaultReject, VaultTx,
    YED_TAG,
};
use kogany_vault::template::{
    IntentParams, TemplateParams, TemplateSpend, SEL_APP, SEL_OWNER, SEL_RELEASED, SEL_UNLOCK,
};
use kogany_vault::{Hash32, PqOwner, Tag};
use kogany_yellowback::attest::SigCache;
use kogany_yellowback::codecs::script::yed_vault_params;
use kogany_yellowback::module::{LruSigCache, YedModule};
use kogany_yellowback::params::regtest_params;

fn set_id(low: u8) -> [u8; 32] {
    // uint256S("0x5e7") etc.: the low bytes first in memory.
    let mut b = [0u8; 32];
    b[0] = low;
    b
}

fn verdict(r: Result<(), VaultReject>) -> String {
    match r {
        Ok(()) => String::new(),
        Err(e) => e.reason().to_owned(),
    }
}

fn spend(vault: bool, selector: u8, p: &kogany_yellowback::params::Params) -> TemplateSpend {
    let owner = PqOwner {
        scheme: 1,
        hash: Hash32([7; 32]),
    };
    let params = if vault {
        TemplateParams::Vault(yed_vault_params(p, &owner, 50))
    } else {
        TemplateParams::Intent(IntentParams {
            tag: YED_TAG,
            recipient_hash: Hash32([1; 32]),
            vault_hash: Hash32([2; 32]),
            delay: 10,
            cancel_set_id: Hash32(p.attestor_set_id),
            set_id: Hash32(p.attestor_set_id),
            owner,
        })
    };
    TemplateSpend {
        params,
        selector,
        sigs: Vec::new(),
    }
}

#[test]
fn module_table_registers_yed() {
    // The primitive's own table: exactly YED (inert there), WYEC never registered.
    assert_eq!(registered_modules().len(), 1);
    assert!(find_module(registered_modules(), &YED_TAG).is_some());
    assert!(find_module(registered_modules(), &Tag(*b"WYEC")).is_none());

    let mut p = regtest_params(10, 0, 0, set_id(0xe7));
    let owner = PqOwner {
        scheme: 1,
        hash: Hash32([7; 32]),
    };
    let good = yed_vault_params(&p, &owner, 50);
    let mut other = good;
    other.set_id = Hash32(set_id(0x99));
    let tx = VaultTx {
        txid: Hash32::ZERO,
        coinbase: false,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    let state = SetState::default();
    let ctx = ModuleContext {
        height: 60,
        state: &state,
        block_hash_at: None,
    };

    // Unconfigured (no attestor set, or no start height, U-22): no module is built, the
    // primitive's inert entry accepts everything (the §5.4 fallback).
    let mut unset = p;
    unset.attestor_set_id = [0u8; 32];
    assert!(YedModule::new(unset, None).is_none());
    let mut no_start = p;
    no_start.start_height = 0;
    assert!(YedModule::new(no_start, None).is_none());
    let inert = find_module(registered_modules(), &YED_TAG).unwrap();
    assert_eq!(verdict(inert.validate_create(&tx, 0, &other, &ctx)), "");
    assert_eq!(
        verdict(inert.validate_spend(&tx, 0, &spend(true, SEL_UNLOCK, &p), &ctx)),
        ""
    );

    // Configured: the YED vault's shape, no set unlock of a YED vault, no owner-released spend
    // of a YED intent.
    let m = YedModule::new(p, None).expect("a configured set");
    let table = m.table();
    let yed = find_module(&table, &YED_TAG).expect("YED\\0 is registered");
    assert!(find_module(&table, &Tag(*b"WYEC")).is_none());
    assert_eq!(yed.governed_set(), Some(Hash32(set_id(0xe7))));
    assert_eq!(verdict(yed.validate_create(&tx, 0, &good, &ctx)), "");
    assert_eq!(
        verdict(yed.validate_create(&tx, 0, &other, &ctx)),
        "bad-yellowback-vault-set"
    );
    let mut cancel = good;
    cancel.cancel_set_id = Hash32(set_id(0x98));
    assert_eq!(
        verdict(yed.validate_create(&tx, 0, &cancel, &ctx)),
        "bad-yellowback-vault-set"
    );
    let mut delay = good;
    delay.delay = i64::from(p.claim_delay) + 1;
    assert_eq!(
        verdict(yed.validate_create(&tx, 0, &delay, &ctx)),
        "bad-yellowback-vault-delay"
    );
    let mut app = good;
    app.app_height = good.owner_height + i64::from(p.grace) + 1;
    assert_eq!(
        verdict(yed.validate_create(&tx, 0, &app, &ctx)),
        "bad-yellowback-vault-height"
    );
    app.app_height = 0;
    assert_eq!(
        verdict(yed.validate_create(&tx, 0, &app, &ctx)),
        "bad-yellowback-vault-height"
    );
    app.app_height = good.owner_height + i64::from(p.grace);
    assert_eq!(verdict(yed.validate_create(&tx, 0, &app, &ctx)), "");
    assert_eq!(
        verdict(yed.validate_spend(&tx, 0, &spend(true, SEL_UNLOCK, &p), &ctx)),
        "bad-yellowback-vault-unlock"
    );
    for sel in [SEL_OWNER, SEL_RELEASED, SEL_APP] {
        assert_eq!(
            verdict(yed.validate_spend(&tx, 0, &spend(true, sel, &p), &ctx)),
            ""
        );
    }
    assert_eq!(
        verdict(yed.validate_spend(&tx, 0, &spend(false, SEL_RELEASED, &p), &ctx)),
        "bad-yellowback-intent-owner"
    );
    for sel in [SEL_UNLOCK, SEL_OWNER] {
        assert_eq!(
            verdict(yed.validate_spend(&tx, 0, &spend(false, sel, &p), &ctx)),
            ""
        );
    }

    // A block without attestor-set acts passes the structural CheckBlock.
    assert_eq!(verdict(yed.check_block(&[tx], &ctx)), "");
    p.attestor_set_id = set_id(0xe8);
    assert_eq!(
        YedModule::new(p, None).unwrap().governed_set(),
        Some(Hash32(set_id(0xe8)))
    );
}

#[test]
fn lru_sig_cache_is_bounded_and_least_recently_used() {
    let c = LruSigCache::new(2);
    let k = |b: u8| Hash32([b; 32]);
    assert_eq!(c.lookup(&k(1)), None);
    c.insert(&k(1), true);
    c.insert(&k(2), false);
    assert_eq!(c.lookup(&k(1)), Some(true)); // 1 is now the most recent
    c.insert(&k(3), true); // evicts 2
    assert_eq!(c.len(), 2);
    assert_eq!(c.lookup(&k(2)), None);
    assert_eq!(c.lookup(&k(1)), Some(true));
    assert_eq!(c.lookup(&k(3)), Some(true));
    c.insert(&k(3), false); // an update keeps the size
    assert_eq!(c.len(), 2);
    assert_eq!(c.lookup(&k(3)), Some(false));
    let (hits, misses) = c.stats();
    assert_eq!((hits, misses), (4, 2));
    c.clear();
    assert!(c.is_empty());
}
