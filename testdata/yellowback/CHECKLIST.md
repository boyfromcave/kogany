# Cross-line vector checklist: schema key → Rust test

Plan §4.2 rule 4 (i): every schema key a C++ test asserts gets a Rust assertion. One section per
pinned vector file, added by the chunk that consumes it. "Not consumed" names the reason a key has
no Rust assertion.

## pq_vectors.json

Consumer: `crates/kogany-pq` (W3-b). C++: ycash6 `src/test/pq_crypto_tests.cpp` (`pq_golden_vectors`,
`pq_round_trip_and_rejects`, `pq_falcon_padding_is_canonical`). Every test loads the file through
`tests/common/mod.rs` `load_pinned`, which checks its SHA-256 against `PIN` first.

| key | Rust test (`crates/kogany-pq/tests/pq_vectors.rs`) |
|---|---|
| `format` | `golden_keys_verify_and_hash` (equals `ycash-pq-vectors-1`) |
| `comment` | not consumed (prose) |
| `keys[].scheme` | `golden_keys_verify_and_hash` (known; ≥ 2 entries per scheme) |
| `keys[].name` | `golden_keys_verify_and_hash` (failure message only) |
| `keys[].label` | not consumed (provenance of seed/msg/entropy; consumers take the hex) |
| `keys[].seed` | `golden_keys_verify_and_hash` (48 bytes only); not replayed: KeyGen is not vendored (K-8, verify-only) |
| `keys[].pk` | `golden_keys_verify_and_hash` (registry size), `rejects_malformed_and_mismatched`, `falcon_padding_is_canonical`, `falcon_rejects_out_of_range_encodings`, `rejects_truncated_and_cross_length_encodings` |
| `keys[].keyhash` | `golden_keys_verify_and_hash` (`key_hash(scheme, pk)`) |
| `keys[].msg` | `golden_keys_verify_and_hash` (32 bytes; signed message) |
| `keys[].entropy` | `golden_keys_verify_and_hash` (0 / 88 bytes only); not replayed: signing is not vendored |
| `keys[].sig` | `golden_keys_verify_and_hash` (registry size, `verify` true), `rejects_malformed_and_mismatched`, `slh_dsa_context_is_empty`, `falcon_padding_is_canonical`, `falcon_rejects_out_of_range_encodings`, `rejects_truncated_and_cross_length_encodings`, `verify_is_thread_safe` |
| `spends[].scheme` | `golden_spends_encode_and_verify` (equals its key's scheme) |
| `spends[].key` | `golden_spends_encode_and_verify` |
| `spends[].scriptPubKey` | `golden_spends_encode_and_verify` (`0x20 ‖ keyhash ‖ OP_n ‖ 0xc2`, 35 bytes) |
| `spends[].hashtype` | `golden_spends_encode_and_verify` (appended to sig; stripped before `verify`) |
| `spends[].sigChunks`, `spends[].pkChunks` | `golden_spends_encode_and_verify` |
| `spends[].scriptSigSize` | `golden_spends_encode_and_verify` |
| `spends[].scriptSig` | `golden_spends_encode_and_verify` (re-encoded byte for byte; parsed back: 520-byte chunks, `OP_n` counts, reassembled sig and pk verify) |

Also from the same C++ file, not a schema key: `registry_sizes` (`pq_sizes_and_registry`, all 256
scheme bytes), `keyhash_commits_the_scheme` (`pq_keyhash`).

## pq_acvp_slhdsa.json

Consumer: `crates/kogany-pq` (W3-b). C++: ycash6 `src/test/pq_crypto_tests.cpp` (`pq_slhdsa_acvp`).

| key | Rust test (`crates/kogany-pq/tests/pq_acvp_slhdsa.rs`) |
|---|---|
| `comment`, `source` | not consumed (prose) |
| `keyGen[]` (count 4) | `acvp_keygen_shapes` |
| `keyGen[].skSeed`, `.skPrf`, `.pkSeed`, `.sk`, `.pk` | `acvp_keygen_shapes` (FIPS 205 layout `PK = PK.seed ‖ PK.root`, `SK = SK.seed ‖ SK.prf ‖ PK`); not replayed: KeyGen is not vendored |
| `keyGen[].tgId`, `.tcId` | not consumed (ACVP bookkeeping) |
| `sigGen[]` (count 5, 2 with empty context) | `acvp_siggen_signatures_verify` |
| `sigGen[].pk`, `.message`, `.context`, `.signature` | `acvp_siggen_signatures_verify` (verifies; fails with the message changed) |
| `sigGen[].sk`, `.deterministic`, `.additionalRandomness` | not consumed: signing is not vendored (the C++ test re-signs) |
| `sigGen[].tcId` | `acvp_siggen_signatures_verify` (failure message); `tgId` not consumed |
| `sigVer[]` (count 9, 2 passes) | `acvp_sigver_verdicts` |
| `sigVer[].pk`, `.message`, `.context`, `.signature`, `.testPassed` | `acvp_sigver_verdicts` (verdict equals `testPassed`) |
| `sigVer[].reason`, `.tcId` | `acvp_sigver_verdicts` (failure message); `tgId` not consumed |

## pq_falcon_kat.json

Consumer: `crates/kogany-pq` (W3-b). C++: ycash6 `src/test/pq_crypto_tests.cpp` (`pq_falcon_kat`).

| key | Rust test (`crates/kogany-pq/tests/pq_falcon_kat.rs`) |
|---|---|
| `comment`, `r3_source` | not consumed (prose) |
| `r3[]` (count 5) | `r3_compressed_signatures_verify_padded` |
| `r3[].count` | `r3_compressed_signatures_verify_padded` (equals index) |
| `r3[].pk` | `r3_compressed_signatures_verify_padded` (verifies; equals `r3_all[n].pk`) |
| `r3[].msg` | `r3_compressed_signatures_verify_padded` (equals the `sm` message field) |
| `r3[].sm` | `r3_compressed_signatures_verify_padded` (layout `len ‖ nonce ‖ msg ‖ 0x29 ‖ s`; padded form verifies and equals `r3_all[n].sig`; compact form refused) |
| `r3[].seed`, `r3[].sk` | not consumed: the NIST DRBG keygen/sign replay needs signing, not vendored |
| `padded[]` (count 1) | `pqclean_padded_kat_verifies` |
| `padded[].pk`, `.msg`, `.sm` | `pqclean_padded_kat_verifies` (`sm = sig(666) ‖ msg`; verifies; a flipped bit fails) |
| `padded[].count`, `.seed`, `.sk` | not consumed: keygen/sign replay, not vendored |
| `r3_all[]` (count 100) | `r3_all_verify_and_reject_one_flip` |
| `r3_all[].count`, `.pk`, `.msg`, `.sig` | `r3_all_verify_and_reject_one_flip` (count = index; sizes 897/666; msg 33·(n+1); verifies; bit 0 of byte 41 + n mod 200 flipped fails) |

## vault_vectors.json

Consumer: `crates/kogany-vault` (W4-a). C++: ycash6 `src/test/vault_vectors_tests.cpp`
(`constants`, `vault_templates`, `intent_templates`, `bond_templates`, `selectors`, `acts`,
`set_sig_messages`, `recoverable_signatures`, `template_spends`, `pq_owner_spends`). Every test
loads the file through `tests/common/mod.rs` `load_pinned`, which checks its SHA-256 against `PIN`
first.

| key | Rust test (`crates/kogany-vault/tests/vault_vectors.rs`) |
|---|---|
| `_comment`, `_schema` | not consumed (prose) |
| `branchId` | `constants` (`0x6d5b7a31`); `template_spends` (each spend's `branchId`) |
| `opcodes.CHECKSEQUENCEVERIFY`, `.CHECKSETSIG`, `.CHECKSETDORMANT` | `constants` (`script::op`) |
| `keys[].secret`, `.pubkey` | `keys_and_owners` (`act::public_key`); `keys[].label` failure message only |
| `pqOwner.owner`, `.pk`, `falconOwner.owner`, `.pk` | `keys_and_owners` (`SHA256(scheme ‖ pk) == owner.hash`, schemes 1 and 2) |
| `pqOwner.seed`, `falconOwner.seed` | `keys_and_owners` (48 bytes only); not replayed: `pq::KeyGen` is not vendored (K-8) |
| `pqOwner.label`, `falconOwner.label` | not consumed (provenance) |
| `vaults[].params`, `.script` | `vault_templates` (`build_vault == script`, `parse_vault == params`, `match_vault` is `Match`, not an I) |
| `vaults[].name` | `vault_templates` (failure message) |
| `vaultsInvalid[].script` | `vault_templates` (`parse_vault` fails), `vault_invalid_shapes_are_classified` (`NotTemplate` vs `Malformed`) |
| `vaultsInvalid[].name`, `.reason` | `vault_invalid_shapes_are_classified` (the class the name implies); `reason` informative |
| `intents[].params`, `.script`, `.recipientScript`, `.vaultScript` | `intent_templates` (`build_intent`, `parse_intent`, `script_hash256`, `intent_for`) |
| `intentsInvalid[].script` | `intent_templates` (`parse_intent` fails); `name`, `reason` informative |
| `bonds[].memberKey`, `.locktime`, `.redeem`, `.spk` | `bond_templates` (`build_bond_redeem`, `bond_script_pubkey`, `parse_bond_redeem`) |
| `selectors[].kind`, `.scriptSig`, `.selector`, `.nArgs` | `selectors` (`parse_template_spend` on `vaults[0]` / `intents[0]`) |
| `selectorsInvalid[].kind`, `.scriptSig` | `selectors` (`parse_template_spend` fails); `reason` failure message |
| `acts[].type`, `.payload` | `acts` (`decode_payload`, `encode_payload` round trip, `act_type`) |
| `acts[].prevout`, `.actMsg` | `acts` (`act_msg`) |
| `acts[].script`, `.sigs`, `.recovered`, `.signers` | `acts` (`is_act_output`, `decode_act` / `encode_act` round trip, each sig `recover_sig` → `recovered`; `signers` count) |
| `acts[].fields` (every field of every type) | `acts` (each decoded field; `SetCreateBody::valid`, `act_fields_valid`, `target_set`) |
| `acts[].convicts` | `acts` (both equivocation sigs recover to it over `set_sig_msg`) |
| `acts[].name` | `acts` (failure message) |
| `actsInvalid[].payload`, `.stage`, `.reason` | `acts_invalid` (`decode`: `decode_payload` fails with the class `reason` names — `version` → `Version`, `type` → `Type`, else `Malformed`; `field`: decodes, `body_fields_valid` / `act_fields_valid` false) |
| `actScriptsInvalid[].script` | `acts_invalid` (`decode_act` fails); `name`, `reason` informative |
| `setSigMsgs[].setId`, `.role`, `.prevout`, `.sighash`, `.msg` | `set_sig_messages` (`set_sig_msg`) |
| `signatures[].secret`, `.pubkey`, `.msg`, `.sig` | `recoverable_signatures` (`sign_recoverable` byte for byte, RFC 6979; `recover_sig` → `pubkey`) |
| `signatures[].lowSFlipped` | `recoverable_signatures` (both branches present) |
| `signatures[].label` | `recoverable_signatures` (failure message) |
| `signaturesInvalid[].msg`, `.sig`, `.nonStrictRecovers` | `recoverable_signatures` (strict `recover_sig` fails; the test's non-strict `RecoverCompact` gives `nonStrictRecovers`); `name`, `reason` informative |
| `spends[].tx`, `.nIn`, `.scriptSig`, `.scriptCode` | `template_spends` (vin[0] prevout and scriptSig from the tx; `parse_template_spend` selector = role) |
| `spends[].setId`, `.role`, `.setSigMsg`, `.signers`, `.sigs` | `template_spends` (`set_sig_msg` over the vin[0] prevout; the scriptSig's sigs equal `sigs` and recover) |
| `spends[].sighash` | `template_spends` (input to `set_sig_msg` only); **not replayed**: the ZIP-243 sighash is the script crate's (W3-c) |
| `spends[].amount`, `.branchId` | not consumed beyond the branch check: they feed the ZIP-243 sighash (W3-c) |
| `ownerSpends[].kind`, `.tx`, `.scriptCode`, `.scriptSig`, `.selector`, `.verify` | `owner_spends_template_half` (template parse, selector 2 for `script`, 3 for `signature`, chunk layout, `SHA256(scheme ‖ pk) == owner.hash`, `SIGHASH_ALL` byte; one Falcon, two released) |
| `ownerSpends[].sighash`, `.amount`, `.branchId`, `.nIn`, `.falconEntropy` | **not replayed here**: `pq::Verify`, `VerifyScript` under the vault flags and the Falcon re-sign are W3 (kogany-pq, the script crate) |
| `ownerSpends[].name` | `owner_spends_template_half` (failure message) |

Sighash replay (W2-c), `crates/zakura-chain/tests/vault_sighash.rs`
(`vault_vector_sighashes_replay_under_the_vault_branch_id`), through Zakura's native v4 (ZIP-243)
sighash under `NetworkUpgrade::Vault`, the file checked against `PIN` first:

| key | Rust assertion |
|---|---|
| `branchId` | equals `NetworkUpgrade::Vault.branch_id()` (the one definition, `network_upgrade.rs`) |
| `spends[].tx`, `.nIn`, `.scriptCode`, `.amount`, `.branchId`, `.sighash` | `Transaction::sighash(Vault, SIGHASH_ALL\|ANYONECANPAY, ..)` equals `sighash`; under Canopy it differs |
| `ownerSpends[].tx`, `.nIn`, `.scriptCode`, `.amount`, `.branchId`, `.sighash` | the same with `SIGHASH_ALL` |

Script verification (W3-c), `crates/zakura-script/src/ycash_tests.rs`, through
`CachedFfiTransaction::is_valid_in` (the consensus entry point) under the flags of a Vault network
and height, the file checked against `PIN` first. C++: `vault_vectors_tests.cpp` `pq_owner_spends`,
`template_spends`.

| key | Rust test |
|---|---|
| `ownerSpends[].tx`, `.nIn`, `.scriptCode`, `.amount` | `vault_vectors_owner_spends_through_the_verifier` (the spent output is `(amount, scriptCode)` for every input; amount + 1 fails) |
| `ownerSpends[].verify` = `script` | the same: selector 2 verifies with any snapshot; Falcon refused with `PqScheme` without the Falcon height, SLH-DSA not; a bad opcode before Vault |
| `ownerSpends[].verify` = `signature` | the same: selector 3 verifies with an unknown set and a dormant one, fails with a live set and with no snapshot |
| `ownerSpends[].kind`, `.selector`, `.falconEntropy` | not consumed here (the template half is W4-a's; the Falcon re-sign needs signing, not vendored) |
| `spends[].tx`, `.nIn`, `.scriptCode`, `.amount`, `.setId`, `.role` | `vault_vectors_set_spends_through_the_verifier` (a snapshot from `acts[set-create]` and `keys[member-0..2]`: verifies; `SetSig` with no snapshot, an unknown set, unmatured seats, removed members, another amount, threshold 3; a bad opcode before Vault) |
| `spends[].signers`, `.sigs`, `.setSigMsg`, `.sighash` | through the same verification (the signatures recover over `set_sig_msg` of the replayed sighash); compared field by field in W4-a / W2-c |

`pq_vectors.json` `spends[].scheme`, `.key`, `.scriptPubKey`, `.scriptSig` and `keys[].msg`:
`pq_vectors_spends_through_the_ycash_checker` (the interpreter with `YcashSignatureChecker`, the
sighash callback returning `msg`: true; another message: false; scheme 2 without Falcon:
`PqScheme`).

Also from ycash6 `src/vault/act.cpp`, not a schema key: `act_carrier_edges` (more than
`MAX_ACT_SIGS` signatures → `bad-vault-act-sigs`, exactly `MAX_ACT_SIGS` decodes, the `"YV"` carrier
test, a header-27 signature decodes but fails the field rules).

## yellowback_math_cases.json

Consumer: `crates/kogany-yellowback` (W5-a). C++: ycash6 `src/test/yellowback_math_tests.cpp`
(`math_spec_rational_cases`). The test checks the file's SHA-256 against `PIN` before replaying it,
in debug and in release (`--release`, `--profile ci-tests`).

| key | Rust test (`crates/kogany-yellowback/tests/math_cases.rs`) |
|---|---|
| `description` | not consumed (prose) |
| `cases` | `math_spec_rational_cases` (67 rows; every row checked, the count asserted) |
| `cases[].fn` | `math_spec_rational_cases` (the eleven functions; an unknown name fails) |
| `cases[].args` | `math_spec_rational_cases` (positional, as the C++ `arg(k)`; mainnet `Params` where the function takes them) |
| `cases[].expect` | `math_spec_rational_cases` (`null` = `None` for the `std::optional` functions; a bool for `IsUnderwater`) |
## Vault set state and `statehash` (W4-b)

Consumer: `crates/kogany-vault` `state` (W4-b). C++: ycash6 `src/test/vault_state_tests.cpp` at
`65cb4ae0f` (40 cases; each is a Rust test of the same name in
`crates/kogany-vault/tests/vault_state.rs`, with the part that belongs to another layer named in
the test's comment), and `vault::StateHash` (`src/vault/node.cpp:505`).

| key | Rust test |
|---|---|
| `vault_vectors.json` | **no state key**: the file pins templates, acts and signatures (W4-a, above); no `statehash` |
| `yellowback_golden.json` `stateHash` | not consumed here: it is `yed_getstatehash` (the YED module's `StateView`, `src/yellowback/view.cpp:458`), W5-d2/W5-e; the chain's vault acts replay there |
| `yellowback_pq_vectors.json` `chain.stateHash` | not consumed here: YED, as above |
| vault `statehash` (`vault_getinfo`) | `crates/kogany-vault/tests/ycash6_statehash.rs` (`statehash_equals_ycash6_vault_rpc`, `statehash_equals_ycash6_vault_slashing`): every block of two regtest chains recorded once from ycashd 6.22.0-rc1 at `65cb4ae0f` running `qa/rpc-tests/vault_rpc.py` and `vault_slashing.py` unmodified (`crates/kogany-vault/tests/data/ycash6_statehash_*.json`, recorder `tests/data/record_statehash.py`; outside the nine-file PIN); the statehash after each of 52 / 53 heights from activation equals ycashd's, then every delta reverts to the empty state |
| `statehash` preimage | `vault_state.rs` `state_hash_preimage` (CompactSize ‖ key ‖ CompactSize ‖ value, key byte order, SHA256d; the empty state) |

## yellowback_pq_vectors.json

Consumer: `crates/kogany-yellowback` (W5-b codecs: `scripts` and the codec layer of `chain`; the
`chain` state replay W5-d1). C++: ycash6 `src/test/pq_channel_tests.cpp`
(`pqchannel_cross_implementation_vectors`) for `scripts`; `src/test/yellowback_state_tests.cpp` for
`chain`. Loaded through `tests/common/mod.rs` `load_pinned` (SHA-256 against `PIN`).

| key | Rust test (`crates/kogany-yellowback/tests/…`) |
|---|---|
| `description` | not consumed (prose) |
| `scripts` (count 364) | `script_tests.rs` `pqchannel_cross_implementation_vectors` (count asserted, > 50 channels) |
| `scripts[].hex`, `.type` | `pqchannel_cross_implementation_vectors` (`match_pq_channel` → `pqchannel`, the TX_PQPKH `holder_key` → `pqpubkeyhash`, else `other`) |
| `scripts[].holder` | `pqchannel_cross_implementation_vectors` (`holder_key`'s PQ key as `scheme ‖ hash`, `""` for none or a P2PKH) |
| `scripts[].name` | `pqchannel_cross_implementation_vectors` (failure message) |
| `chain.params.*` | `golden_codecs.rs` `pq_chain_codecs` (the regtest column; `attestorSetId` in `uint256` display order) |
| `chain.blocks[].height`, `.txs` | `pq_chain_codecs` (every coinbase through `find_tag`, every tx through `find_payload` / `find_carrier_input`, re-encoded byte for byte; each MINT's V equals `yed_vault_script`; the census of kinds asserted) |
| `chain.blocks[].hash`, `.subsidyZat`, `chain.invalid[]`, `chain.stateHash`, `chain.tip`, `chain.totals` | `yellowback_state_golden.rs` `pq_vectors_chain_across_falcon` (W5-d1): every block through `evaluate_block` over the running `YedState` (block hash in display order, the subsidy as given); the six invalid blocks are exactly `chain.invalid[]` (height and verdict) and the rest apply; `state_hash` equals `chain.stateHash`, the tip height and `totals.supplyCents` / `.activeVaults` equal; reverting every delta restores the empty state |

## yellowback_golden.json

Consumer: `crates/kogany-yellowback` (W5-b: the codec layer; W5-d1: the replay to `stateHash` /
`totals` through the state machine; W5-f: the same through the registered module). C++: ycash6 `src/test/yellowback_state_tests.cpp`.

| key | Rust test (`crates/kogany-yellowback/tests/golden_codecs.rs`) |
|---|---|
| `description` | not consumed (prose) |
| `params.*` | `golden_chain_codecs` (the regtest column, as `pq_chain_codecs`) |
| `blocks[].height`, `.txs` | `golden_chain_codecs` (as `pq_chain_codecs`; the census asserted: 460 tags of 461 patterns — height 13's tag sets a reserved flag bit —, 11 MINT, 4 TRANSFER, 17 REDEEM, 1 REGISTER, 3 NOTICE, 2 EQUIVOCATION, 7 CANCEL_COSIGN, 25 carriers whose bundle hashes match) |
| `blocks[].hash`, `.subsidyZat`, `stateHash`, `tip`, `totals` | `yellowback_state_golden.rs` `statehash_golden_vector` (W5-d1; the registered-module replay is still W5-f's gate): 440 blocks apply, the 22 rejected blocks (`blocks[].invalid`) are rejected with the C++ verdicts in order; `state_hash` equals `stateHash` (`ee6a9f15…0c0b`), `tip.height` / `tip.hash`, all eight `totals` fields equal; the open-debt invariant holds; every vault carries a `pMint`; reverting every delta restores the empty state. `yellowback_state_records_tests.rs` `golden_state_decodes_from_its_canonical_bytes`: every key and record of the final state decodes back from its canonical bytes |

## pq_wallet_vectors.json

Consumer: `crates/kogany-yellowback` (W5-b: the owners' addresses). C++: none on the node side
(the HKDF derivation is the wallets', quantum spec A-12).

| key | Rust test (`crates/kogany-yellowback/tests/address_tests.rs`) |
|---|---|
| `format` | `pq_wallet_vectors_owner_addresses` (equals `ycash-pq-wallet-vectors-1`) |
| `hdSeed.slh.pk`, `.keyhash`, `mnemonic.slh.pk`, `.keyhash` | `pq_wallet_vectors_owner_addresses` (`kogany_pq::key_hash(1, pk) == keyhash`; the owner's 53-character address round-trips on main, test and regtest); `slh.index` asserted 0 |
| `_comment`, `info`, `hdSeed.ikm`, `hdSeed.derive[]`, `mnemonic.entropy`, `.phrase`, `.ikm`, `.derive[]` | **not consumed here**: HKDF-SHA256 key derivation and BIP39 are wallet code (the `yewd` sidecar, S-track), not the node |

Also from ycash6, not a schema key: the payload, script, address and tag cases of
`src/test/yellowback_{payload,script,address,tag}_tests.cpp` (`tests/{payload,script,address,tag}_tests.rs`,
the C++ test names kept), and PQ-address known answers computed with ycash6's
`qa/rpc-tests/test_framework/yellowback_model.py` (`pq_addresses_53_characters_known_answers`).

## yellowback_attest_vectors.json

Consumer: `crates/kogany-yellowback` (W5-c). C++: ycash6 `src/test/yellowback_attest_tests.cpp`
(`message_layout`, `vectors_verify`, `highs_rejected`, `invalid_vectors_rejected`,
`shared_vector_list`, `codec`) and `src/test/yellowback_bundle_tests.cpp` (`Fixture`,
`codec_round_trip_and_sizes`, `verify_order_every_reason`, `sig_cache_contract`, `bundle_stat`).
Every test loads the file through `tests/common/mod.rs` `load_pinned`.

| key | Rust test (`crates/kogany-yellowback/tests/yellowback_{attest,bundle}_tests.rs`) |
|---|---|
| `_comment` | not consumed (prose) |
| `prefix` | `message_layout` (equals `YBATTEST1`) |
| `keys[]` (count 6), `.seq`, `.secret`, `.pubkey` | `vectors_verify` (the secret derives the pubkey; re-signs each valid vector with RFC 6979 to its `sig`); the bundle `Fixture` (seq → key) |
| `valid[]` (count 8) | `vectors_verify`, `highs_rejected` (8 seen); the bundle `Fixture` (first six seq 0..5, then seq 0 at 1002 and seq 1 at 1003) |
| `valid[].seq`, `.priceMicroUsd`, `.citedHeight`, `.blockHashInternal` | `message_layout` (`attest_message` equals `message`) |
| `valid[].blockHash` | `message_layout` (the reversed hex of `blockHashInternal`) |
| `valid[].message` | `message_layout`, `vectors_verify`, `highs_rejected` |
| `valid[].pubkey`, `.sig` | `vectors_verify` (verifies; equals the re-signed signature), `highs_rejected` |
| `valid[].sigHighS` | `highs_rejected` (refused; same `r`, differs from `sig`) |
| `valid[].attestation` | `vectors_verify` (`encode_attestation` of the parts); the bundle `Fixture` (decoded) |
| `invalid[]` (count 5), `.name`, `.seq`, `.priceMicroUsd`, `.citedHeight`, `.blockHashInternal`, `.pubkey`, `.sig` | `invalid_vectors_rejected` (every one refused; `high_s`, `wrong_block_hash`, `wrong_key` present), `highs_rejected` (`high_s`) |
| `invalid[].why` | `invalid_vectors_rejected` (non-empty; prose) |
| `bundle6` | `codec_round_trip_and_sizes` (`encode_bundle` of the first six valid attestations, 448 bytes) |
| `vectors[]` (count 15: 10 valid, 5 invalid, 2 regtest) | `shared_vector_list` |
| `vectors[].attestation`, `.seq`, `.price`, `.citedHeight` | `shared_vector_list` (decodes to the fields) |
| `vectors[].blockHash` (display form), `.pubkey`, `.valid` | `shared_vector_list` (verifies iff `valid`) |
| `vectors[].secret` | `shared_vector_list` (valid rows: derives `pubkey`, re-signs to the attestation's `sig`; the regtest rows' secret is `sha256("yellowback-regtest-attestor-0")`) |
| `vectors[].name` | `shared_vector_list` (the `regtest-attestor-0` rows: fixed pubkey, block hash `00…01`) |

Also from ycash6, not a schema key: the rest of `yellowback_bundle_tests.cpp`
(`extract_positions_and_modes`, `cancel_cosign_codecs`; `tests/yellowback_bundle_tests.rs`); the
attest cases of `yellowback_state_tests.cpp` (`selected_matches_python`,
`seat_eviction_victim_rule`, `weight_clamped_before_trigger`, `founding_cohort_origin`,
`seating_ties_by_seq`, `selected_excludes_pinned`, `default_attest_payee_in_A`,
`attestor_set_adopted_only_with_threshold_one`, `p4b_slashed_key_barred_remove_winddown_refused`
on a registry-only fixture; `tests/yellowback_attest_state_tests.rs`, which also checks the
mirror's set acts, bond spends, EQV-1, liveness credit, the SNAP attestor passes, the record
encodings, `VerifyTxBundle`'s statistic, the bundle log and the fee price); and the YED halves of
`vault_state_tests.cpp` (`module_ejection_hook_eqv1_yed`, `module_ejection_hook_cancel_statement`,
`module_liveness_hook`, plus displacement and `CheckBlock`; `tests/yellowback_attest_hooks_tests.rs`).
The attest cases that need mints, prices or vaults (`mint9_*`, `red1_claim_needs_bundle`,
`afee1_*`, `cancel_cosign_*`, `cancel_statement_*`, `dormancy_needs_selection_evidence`,
`liveness_needs_held_act_and_fresh_ref`, `pin2_excludes_seq`, `rev1_*`, `dq28_*`, `undo_identity_v3`)
are the state machine's (W5-d1/d2), over this module's API; the signature cache's LRU
(`yellowback_index_tests.cpp` `sigcache_lru_and_hit_equals_cold`) is the index's (W5-e).

## yellowback_state_tests.cpp: the case split (W5-d1, W5-d2, W5-e)

Consumer: `crates/kogany-yellowback` `state` (W5-d1). C++: ycash6 `src/test/yellowback_state_tests.cpp` at
`65cb4ae0f` (159 cases). Each ported case is a Rust test of the same name over `tests/state_common/fixture.rs`
(the port of the C++ `Fixture`, `MintOpts`, `SpendOpts`, `MintVerdictOf`, `Spend`, `VerdictOf`,
`EmergencyFixture`; deterministic keys where the C++ draws random ones).

**W5-d1, ported (84):**
- chains (`tests/yellowback_state_golden.rs`): `statehash_golden_vector`, `pq_vectors_chain_across_falcon`;
- MINT, TRANSFER, TX-0 (`tests/yellowback_state_mint_tests.rs`): `mint1_wellformed_creates_vault_and_token`,
  `tx0_coinbase_payload_registers_nothing`, `mint2_every_clause_voids`, `mint2_regtest_height_underflow`,
  `mint3_outputs_owner_key_vault_script`, `mint3_tokpq_falcon_height_boundary`, `mint4_not_active_and_halts`,
  `mint4_divergence_and_global_ratio`, `mint4_requires_armed`, `mint2_disabled_class_refused`,
  `recap_floor_is_the_class_minimum_with_sigma`, `mint5_collateral_and_unsatisfiable`,
  `mint7_token_output_is_not_the_opreturn`, `mint8_fee_edges`, `in3_mint_with_yed_inputs_burns_them`,
  `xfer1_xfer2_xfer3_and_burns`;
- ARMED mints and the attest cases W5-c left to the state machine (`tests/yellowback_state_mint_attest_tests.rs`):
  `mint9_no_bundle_void`, `mint9_bundle_from_unselected_void`, `mint9_stale_attestation_void`,
  `mint10_diverged_void`, `mint10_reads_the_fast_median_so_a_rally_mints`, `mint10_exact_boundary_ok`,
  `price2_unarmed_reads_x_only`, `price2_min_max`, `mint8_lower_bound_before_mint9`, `afee1_fee_to_contributor`,
  `afee0_unarmed_vacuous`, `attest_required_false_reads_x_only`, `pin2_excludes_seq`,
  `rev1_heartbeat_revives_s15_dormant`, `dq28_bond_min_from_collateral`;
- claims into intents (`tests/yellowback_state_claim_tests.rs`): `red4_claim_path_underwater_at_r`,
  `red4_undefined_pclaim`, `red1_claim_needs_bundle`, `red4b_needs_notice_and_persist`, `red4b_notice_too_old`,
  `red4b_before_arming_false`, `red5_residual_paid`, `red5_residual_below_dust_vacuous`,
  `red5_residual_to_wrong_key_invalid`, `red5a_roles_are_positional_and_the_claimant_is_floored`,
  `red5b_path_b_caps_at_p_emerg`, `red5_normal_claim_residual_zero`, `red5_residual_threshold_at_p_mint`,
  `not1_standing_notice_not_replaced`, `in_term_vault_app_height_is_mint_height`,
  `in_term_old_shape_vault_spendable_but_not_mintable`, `in_term_claim_valid_at_theta_invalid_above`,
  `in_term_claim_valid_post_term_as_before`, `in_term_emergency_claim_pays_the_residual_to_the_owner`,
  `in_term_recap_gate_is_class_c_only`, `in_term_sigma_multiplier_fixed_at_one`,
  `in_term_halt_ratio_counts_claiming_vault`;
- cancels (`tests/yellowback_state_cancel_tests.rs`): `intent_cancel_recreates_the_vault_at_vout0`,
  `intent_claim_records_the_refund_holder`, `intent_cancel_without_refund_invalid`,
  `intent_cancel_refund_at_lowest_holder_output`, `intent_cancel_yed_inputs_still_burn`,
  `intent_cancel_refund_spendable_and_reclaims`, `intent_cancel_refund_transferable`,
  `intent_cancel_refund_crosses_the_falcon_boundary`, `intent_cancel_of_residual_invalid`,
  `intent_cancel_relock_not_vout0_invalid`, `intent_cancel_two_relocks_invalid`,
  `intent_cancel_relock_script_differs_invalid`, `intent_cancel_payload_or_selector3_malformed`,
  `intent_cancel_erases_the_notice`, `intent_cancel_undo_roundtrip`, `cancel_limit_constants_per_network`,
  `cancel_limit_escalation_schedule_and_cap`, `cancel_limit_quiet_resets_the_schedule`, `cancel_cosign_refusals`,
  `cancel_cosign_counts_distinct_valid_entries`, `cancel_cosign_holds_when_a_cosigner_leaves_in_the_same_block`,
  `cancel_limit_counter_undo_byte_identical`, `cancel_limit_residual_held_until_quiet`,
  `cancel_limit_residual_release_mirrors_every_citable_ref`, `cancel_limit_residual_armed_pool_low_fails_closed`,
  `cancel_limit_residual_held_while_claimable_by_path_b`, `cancel_limit_residual_released_when_the_position_closes`,
  `cancel_limit_residual_follows_the_position_and_holds_while_claiming`,
  `cancel_limit_residual_of_a_released_claim_unchanged`, `cancel_statement_slashed_by_eqv1`,
  `cancel_statement_honest_canceller_never_slashed`.

Beyond the C++ list (`tests/yellowback_state_records_tests.rs`): `keys_order_is_byte_order`,
`record_encodings_round_trip_with_the_cpp_sizes`, `golden_state_decodes_from_its_canonical_bytes`,
`delta_applies_reverts_and_inverts`, `process_tx_returns_writes_and_leaves_the_base`.

**W5-d2, ported (61; release, owner redeem and the early fee, SNAP's price/halt/sigma/tag rules, the supply cap,
EQV-1 and the mirror through the state, PIN-1, dormancy, ARM, liveness, FEE-W, the mempool check):**
- owner redeem, IT-9, NOT-1 on close, MINT-6/6b (`tests/yellowback_state_redeem_tests.rs`):
  `red_owner_redeem_passes_and_closes`, `red2_missing_and_short_burn`, `in3_burn_recorded_on_closed_vault`,
  `red3_fee_and_payee_edges`, `red1_structure_and_selectors`, `m3_vault_spend_with_mint_payload`,
  `red1_owner_path_ignores_bundle`, `in_term_owner_redeem_below_theta_before_any_claim`,
  `in_term_early_redeem_fee_per_class_and_boundary`, `not1_deleted_when_vault_closes`, `mint6_supply_cap`,
  `mint6_cap_is_soft_above_the_recap_floor`, `mint6_issued_seeded_with_the_circulating_supply`, `mint6b_vault_share`;
- SNAP, FEE-W, chaining, totality, HALT-2's invariant (`tests/yellowback_state_snap_tests.rs`):
  `tag3_signal_only_registers_nobody`, `price1_half_fill_boundary_and_selectors`, `price1_mid_slow_need_two_thirds`,
  `halt2_halt3_clear_with_undefined_price`, `halt2_fires_at_exact_threshold`, `halt3_fires_on_mid_vs_slow`,
  `sigma1_undefined_sample_gives_cap`, `sigma1_one_pool_cannot_inflate`, `reg4_judgement_lag_and_bands`,
  `fee2_eligible_set_window_edges`, `fee1_floor_dominates_small_vault`, `feew_accuracy_tilt_ratio`,
  `feew_penalised_skipped_and_fallback`, `feew_override_flags_change_pick`, `tpl1_overlay_order_in_block_chaining`,
  `totality_every_lookup_misses`, `virtual_snapshot_below_start_height`, `snapshot_undefined_price_is_zero`,
  `snap_written_for_every_height_ge_start`, `params_selected_by_height`, `mempoolcheck_bench` (the EvaluateBlock half
  at 200 ms, and 10,000 plain transactions through `mempool_check_reason` at 1 s; both budgets x10 in debug or by
  `YELLOWBACK_BENCH_SCALE`, as `BenchBudgetScale`), `halt2_open_debt_totals_invariant_and_undo`;
- the mirror and the attestor passes through the state (`tests/yellowback_state_mirror_tests.rs`):
  `p4b_register_and_revive_payloads_invalid`, `p4b_join_mirrors_member`, `p4b_rejoin_after_withdraw_new_seq`,
  `p4b_set_dormancy_and_heartbeat_revival`, `p4b_attestor_set_adopted_only_open_15`, `seat_eviction_mirror`,
  `liveness_needs_held_act_and_fresh_ref`, `attestor_seq_exhausted`, `arm1_triggers_at_exact_block`,
  `arm2_arms_after_delay`, `arm_never_reverses`, `eqv1_two_prices_one_hash_ejects`, `eqv1_fork_hashes_not_equivocation`,
  `dormancy_needs_selection_evidence`, `dormancy_unseated_never_dormant`, `dormancy_only_at_check_heights`,
  `pin1_arms_from_bundlelog`, `pin1_excludes_key_from_medians_and_E`, `pin_not_armed_without_bundles`,
  `pin1_ignores_undefined_amint`, `in2_bond_spend_withdraws`, `seated_since_tracks_seating`,
  `selection_ignores_owner_key`, `cache_hit_equals_cold`, `r12_failing_notice_leaves_no_bundle_row`.

The functions these read (`src/state/policy.rs`, `src/state/mempool.rs`): `registered`, `penalized`, `accuracy_bps`,
`PayeePolicy`, `default_payee` (REG-1..3, FEE-W), `open_debt_invariant_violation` (HALT-2), `halt_mask_names`, and
`mempool_check_reason` (`index.cpp` `MempoolCheckInner`). Beyond the C++ state list
(`tests/yellowback_state_mempool_tests.rs`): `mempool_check_reasons` (the reasons of `yellowback_index_tests.cpp`
`mempoolcheck_bench` that need no index), `mempool_check_refuses_attestor_set_act`, `mempool_check_gates`.

The count, by name against the C++ file at `65cb4ae0f`: 161 `BOOST_AUTO_TEST_CASE`s = 86 W5-d1 + 9 W5-c + 61 W5-d2 +
the 5 W5-e cases below (the "159" and "84" above predate a recount). The other `src/test/yellowback_*_tests.cpp`
files hold no further state-machine case for W5: their supply-cap and HALT-2 arithmetic is W5-a's
(`math_unit.rs` `mint6_market_cap_and_supply_cap`, `halt2_global_ratio`; `params_tables.rs`
`halt2_floor_below_every_enabled_class_ratio`), the `yellowback_pq_vectors.json` matcher is W5-b's
(`script_tests.rs` `pqchannel_cross_implementation_vectors`, TOK-PQ in `holderkey_pq_holder_recognition`), and
`yellowback_index_tests.cpp` (`invariant_audit_catches_a_corrupt_total`, the fee price, the storage faults, the
sweep) and `yellowback_fuzz_tests.cpp` (`evaluate_corpus_replay`, `payee_corpus_replay`) run through the index or a
serialised-block harness (W5-e / W6).

**W5-e (the index as consensus state; their state-level halves may be ported by W5-d2 over `YedState`):**
`apply_undo_identity_over_sequences`, `p_mint_persists_through_undo_and_reapply`, `overlay_view_equivalence`,
`undo_identity_v3`, `overlay_equivalence_v3` — over the column-family store and `UpdateWith`.

Ported by W5-c on a registry-only fixture (`tests/yellowback_attest_state_tests.rs`), not repeated here:
`selected_matches_python`, `seat_eviction_victim_rule`, `weight_clamped_before_trigger`, `founding_cohort_origin`,
`seating_ties_by_seq`, `selected_excludes_pinned`, `default_attest_payee_in_A`,
`attestor_set_adopted_only_with_threshold_one`, `p4b_slashed_key_barred_remove_winddown_refused`.
