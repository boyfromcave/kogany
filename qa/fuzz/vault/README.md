# Vault fuzz verdict replay (kogany, W3-e)

kogany's parsers for the vault upgrade must classify every byte string exactly as ycash6 does.
This package checks that against **verdicts recorded once from ycash6** (plan
`docs/plans/kogany/kogany-yellowback-plan.md` W3-e; lane-E survey §3, rule 4: verdict replay, no
live cross-language fuzzing).

| Path | What |
|---|---|
| `verdicts/<Corpus>.tsv` | `name ‖ sha256(input) ‖ hex(input) ‖ verdict`, recorded from ycash6 `65cb4ae0f`. Never edit. |
| `recorder/record_verdicts.cpp` | the ycash6 side: each input through the C++ parsers, one verdict string per input |
| `record_verdicts.py` | builds the recorder against a ycash6 build tree and writes `verdicts/` |
| `src/verdict.rs` | the kogany side: the same verdict string from kogany's parsers |
| `fuzz_targets/vault_verdicts.rs` | the libFuzzer target: all four verdict formats over any input, the round trips, and ycash6's verdict on a recorded input |

The deterministic gate is the replay test, run on the `ycash` build:

```console
cargo test --locked -p zakura-consensus --features ycash --test vault_fuzz_verdicts
```

`qa/suite.toml` lists it as the lane `kogany/vault-fuzz-verdicts`, and the fuzz target as the
`vault` package's `vault_verdicts`. Run the target as the other fuzz packages are run:

```console
cargo +nightly-2026-07-15 fuzz run --fuzz-dir qa/fuzz/vault vault_verdicts
```

This package is a workspace of its own and copies the root `[patch.crates-io]` (the `ycash`
feature needs the common fork). Keep that section equal to the root's.

## Corpora

| Corpus | Inputs | Source | Verdict format |
|---|---|---|---|
| `Vault` | 375 | ycash6 `src/fuzzing/Vault/input` | `Vault` |
| `YellowbackScript` | 539 | ycash6 `src/fuzzing/YellowbackScript/input` | `YellowbackScript` |
| `YellowbackPayload` | 303 | ycash6 `src/fuzzing/YellowbackPayload/input` | `YellowbackPayload` |
| `YellowbackTag` | 289 | ycash6 `src/fuzzing/YellowbackTag/input` | `YellowbackTag` |
| `PQVectors` | 364 | `testdata/yellowback/yellowback_pq_vectors.json` `"scripts"` (PIN-checked) | `YellowbackScript` |
| `PQPKH` | 1,865 | `record_verdicts.py` `pqpkh_inputs()`: the TX_PQPKH byte neighbourhood and the other destination kinds | `YellowbackScript` |

The four C++ corpora hold no TX_PQPKH script and the pinned vectors two, so `PQPKH` adds the
neighbourhood: every scheme opcode, every final opcode, every first byte, every append and every
prefix of the 35-byte script, the PUSHDATA1, 31- and 33-byte forms, and P2PKH, P2SH, P2PK (each
header byte) and multisig. Its inputs are built in kogany; its verdicts, like every corpus's,
come from ycash6.

Not replayed (each needs a later wave's layer): `PQScript` (an `OP_CHECKPQSIG` stack grammar for
the interpreter: the fork's W3-a cases and W3-c), `VaultState` (the set state machine, W4-b/W4-e),
`YellowbackEvaluate` (block evaluation, W5-d/W5-f), `YellowbackBundle` (attestations, W5-c),
`YellowbackPayee` (the payee schedule, W5-d).

## Verdict formats

Fields are `key=value`, joined by `;`, in this order. `d8(x)` is the first 8 bytes of SHA-256(x),
in hex.

- Every script verdict starts `kind=<Solver type>;dest=<ExtractDestination>`: `kind` is one of
  `nonstandard pubkey pubkeyhash scripthash multisig nulldata vault vaultintent pqpubkeyhash
  pqchannel` (kogany: `ycash_standard_script_kind`, then `match_pq_channel`, `parse_vault`,
  `parse_intent`); `dest` is `none`, `key:<20>`, `script:<20>` or `pq:<scheme>:<32>`
  (kogany: `transparent::Script::destination`).
- `Vault` (input `u16 LE n ‖ spk ‖ scriptSig`, as `vault_fuzz::Split`): over the spk, `V` and
  `I` = `none|match|malformed` (`MatchVault`/`MatchIntent`), `bond=0|1` (`ParseBondRedeem`),
  `act=ok:<type>:<sigs>:<ActFieldsValid>` or the reject reason (`DecodeAct`), `P=` the same for
  the spk bytes as a bare payload (`DecodePayload`); over the scriptSig, `sel=<n>:<pushes>:<d8>`
  or `none` (`ParseSelector`), and `ts=v|i:<selector>:<sigs>` or `none` (`ParseTemplateSpend`).
- `YellowbackScript` (the input as one script): `v2=<lock>:<claim>` (`ParseVaultScript`),
  `path=<owner>:<pushes>:<d8 selector>:<d8 ownerSig>` (`ParseVaultSpendPath`),
  `redeem=<len>:<d8>` (`ExtractRedeemScript`), `holder=` a destination (`HolderKey`),
  `chan=<scheme>:<refundHeight>` (`MatchPQChannel`), `carrier=0|1` (`IsCarrierScript`),
  `bond=<locktime>` (`ParseBondScript`); each `none` when it does not parse.
- `YellowbackPayload`: `payload=<type>` (`DecodePayload`), `opret=<len>`
  (`ExtractOpReturnData(PayloadScript(input))`), `found=<vout>:<type>` (`FindPayload` over the
  outputs `[input, PayloadScript(input)]`), then the script fields of the input.
- `YellowbackTag` (input `u32 LE height ‖ scriptSig`): `tag=<flags>:<price>:<mask>:<payout>`
  (`FindTag`) and `h=` six `0|1` for `FindTag(input, h)` at heights 0, 1, 16, 17, 65535, 1234567.

Re-record (a ycash6 pin bump only):

```console
$WS/.venv/bin/python qa/fuzz/vault/record_verdicts.py --ycash6-build $WS/wt/kc-harness
```
