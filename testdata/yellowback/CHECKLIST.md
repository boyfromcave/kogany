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

## yellowback_pq_vectors.json

Consumer: `crates/kogany-yellowback` (W5-b codecs: `scripts` and the codec layer of `chain`; the
`chain` state replay is W5-d2). C++: ycash6 `src/test/pq_channel_tests.cpp`
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
| `chain.blocks[].hash`, `.subsidyZat`, `chain.invalid[]`, `chain.stateHash`, `chain.tip`, `chain.totals` | **not yet**: the state machine and the state hash (W5-d2, W5-e/f) |

## yellowback_golden.json

Consumer: `crates/kogany-yellowback` (W5-b: the codec layer; the replay to `stateHash` / `totals`
is W5-f). C++: ycash6 `src/test/yellowback_state_tests.cpp`.

| key | Rust test (`crates/kogany-yellowback/tests/golden_codecs.rs`) |
|---|---|
| `description` | not consumed (prose) |
| `params.*` | `golden_chain_codecs` (the regtest column, as `pq_chain_codecs`) |
| `blocks[].height`, `.txs` | `golden_chain_codecs` (as `pq_chain_codecs`; the census asserted: 460 tags of 461 patterns — height 13's tag sets a reserved flag bit —, 11 MINT, 4 TRANSFER, 17 REDEEM, 1 REGISTER, 3 NOTICE, 2 EQUIVOCATION, 7 CANCEL_COSIGN, 25 carriers whose bundle hashes match) |
| `blocks[].hash`, `.subsidyZat`, `stateHash`, `tip`, `totals` | **not yet**: the golden replay (W5-f) |

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
