//! The vault primitive's read RPCs (`ycash6/doc/vault-rpc.md`, "Read RPCs"; `src/rpc/vault.cpp`
//! `vault_getinfo`, `set_list`, `set_getinfo`, `vault_list`, `vault_decodescript`).

use std::sync::Arc;

use kogany_vault::{
    act::{decode_act, encode_payload, is_act_output},
    template::{
        hash160, is_known_pq_scheme, match_intent, match_vault, p2sh_script_pubkey,
        parse_bond_redeem, parse_intent, parse_vault, Shape,
    },
    Hash32, PqOwner, SetId, Tag,
};
use serde::Deserialize;
use zakura_chain::{parameters::Network, transparent};
use zakura_rpc::server::{error::LegacyCode, jsonrpc::RpcResult};

use crate::{
    json::{display_hex, parse_display_hash, parse_hex, raw_hex, rpc_error, Yec},
    state::{TemplateKind, VaultReadState, VaultSnapshot, VaultStateView},
    types::{
        ActBodyJson, ActSigJson, DbTipJson, DecodedScript, IntentFieldsJson, SetJson,
        TemplateOutJson, VaultFieldsJson, VaultInfo,
    },
};

/// The Vault upgrade's consensus branch ID (ycash6 `UPGRADE_VAULT`), as `vault_getinfo` writes it.
pub const VAULT_BRANCH_ID_HEX: &str = "6d5b7a31";

/// `vault_list`'s optional filter.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct VaultListFilter {
    /// 1-4 ASCII characters (zero-padded) or 8 hex digits.
    pub tag: Option<String>,
    /// Matches either set of the template.
    pub setid: Option<String>,
    /// A pqkeyid (66 hex digits).
    pub owner: Option<String>,
    /// `"vault"` or `"intent"`.
    pub kind: Option<String>,
    /// Whether the owner key is in this wallet: kogany has none (K-3), so only `false` is taken.
    pub mine: Option<bool>,
}

crate::kogany_rpc_trait! {
    /// The vault primitive's read RPCs, as kogany serves them.
    ///
    /// They answer from a [`VaultReadState`] (plan W4-d) and need no wallet. Unlike ycashd they
    /// omit the wallet-derived fields (`wallet` on members and template outputs) and refuse
    /// `vault_list`'s `mine: true` (plan K-3: kogany has no wallet).
    pub trait VaultRpc {
        /// The vault upgrade and its set-state database (doc/vault-rpc.md `vault_getinfo`).
        #[method(name = "vault_getinfo", access = Unauthenticated)]
        async fn vault_getinfo(&self) -> RpcResult<VaultInfo>;

        /// Every signer set at the next block, without member lists (`set_list`).
        #[method(name = "set_list", access = Unauthenticated)]
        async fn set_list(&self) -> RpcResult<Vec<SetJson>>;

        /// One signer set with its members, its predicates at `height` (default: the next
        /// block) over the state at the tip (`set_getinfo "setid" ( height )`).
        #[method(name = "set_getinfo", access = Unauthenticated)]
        async fn set_getinfo(&self, setid: String, height: Option<i64>) -> RpcResult<SetJson>;

        /// The unspent vault and intent outputs, optionally filtered
        /// (`vault_list ( {"tag", "setid", "owner", "kind"} )`).
        #[method(name = "vault_list", access = Unauthenticated)]
        async fn vault_list(&self, filter: Option<VaultListFilter>) -> RpcResult<Vec<TemplateOutJson>>;

        /// Decodes a vault V or intent I scriptPubKey, a `YV` act OP_RETURN or a member bond B
        /// redeem script (`vault_decodescript "hex"`).
        #[method(name = "vault_decodescript", access = Unauthenticated)]
        async fn vault_decodescript(&self, hex: String) -> RpcResult<DecodedScript>;
    }
    dispatch = VaultRpcDispatch;
}

/// [`VaultRpc`] over a [`VaultReadState`].
#[derive(Clone)]
pub struct VaultRpcImpl {
    state: Arc<dyn VaultReadState>,
    network: Network,
}

impl VaultRpcImpl {
    /// The read RPCs over `state`, for `network` (its address encoding).
    pub fn new(state: Arc<dyn VaultReadState>, network: Network) -> Self {
        Self { state, network }
    }

    /// These methods as a server extension.
    pub fn into_extension(self) -> zakura_rpc::server::kogany_extension::RpcExtension {
        VaultRpcDispatch(self).into_extension()
    }

    async fn snapshot(&self) -> RpcResult<VaultSnapshot> {
        self.state.snapshot().await.map_err(|message| {
            zakura_rpc::server::jsonrpc::ErrorObject::new(
                zakura_rpc::server::jsonrpc::ErrorCode::InternalError,
                message,
            )
        })
    }

    /// The database, or ycash6's `Snapshot()` error.
    fn db(snapshot: &VaultSnapshot) -> RpcResult<&Arc<dyn VaultStateView>> {
        snapshot.db.as_ref().ok_or_else(|| {
            zakura_rpc::server::jsonrpc::ErrorObject::new(
                zakura_rpc::server::jsonrpc::ErrorCode::InternalError,
                "the vault database is not available",
            )
        })
    }
}

#[async_trait::async_trait]
impl VaultRpc for VaultRpcImpl {
    async fn vault_getinfo(&self) -> RpcResult<VaultInfo> {
        let snapshot = self.snapshot().await?;
        let upgrade = snapshot.upgrade;
        let mut info = VaultInfo {
            branchid: VAULT_BRANCH_ID_HEX.to_owned(),
            activationheight: upgrade.activation_height.unwrap_or(-1),
            active: upgrade.active_at_next,
            height: upgrade.tip_height,
            attestorsetid: upgrade.attestor_set_id.as_ref().map(display_hex),
            moduleactive: upgrade.attestor_set_id.is_some(),
            dbtip: None,
            sets: None,
            vaults: None,
            intents: None,
            lockedvalue: None,
            statehash: None,
        };
        let Some(db) = snapshot.db else {
            return Ok(info);
        };
        info.dbtip = db.db_tip().map(|tip| DbTipJson {
            hash: display_hex(&tip.hash),
            height: tip.height,
        });
        let (mut vaults, mut intents, mut locked) = (0u64, 0u64, 0i64);
        for out in db.template_outputs() {
            match out.kind {
                TemplateKind::Vault => {
                    vaults = vaults.saturating_add(1);
                    locked = locked.saturating_add(out.value);
                }
                TemplateKind::Intent => intents = intents.saturating_add(1),
            }
        }
        // A usize count fits in a u64 on every supported platform.
        info.sets = Some(db.set_ids().len() as u64);
        info.vaults = Some(vaults);
        info.intents = Some(intents);
        info.lockedvalue = Some(Yec(locked));
        info.statehash = Some(display_hex(&db.state_hash()));
        Ok(info)
    }

    async fn set_list(&self) -> RpcResult<Vec<SetJson>> {
        let snapshot = self.snapshot().await?;
        let db = Self::db(&snapshot)?;
        let next = snapshot.upgrade.tip_height.saturating_add(1);
        Ok(db
            .set_ids()
            .iter()
            .filter_map(|id| db.set(id, next))
            .map(|set| SetJson::new(&set, next, false))
            .collect())
    }

    async fn set_getinfo(&self, setid: String, height: Option<i64>) -> RpcResult<SetJson> {
        let snapshot = self.snapshot().await?;
        let db = Self::db(&snapshot)?;
        let id = parse_display_hash(&setid, "setid")?;
        let at = match height {
            Some(h) if h < 0 => {
                return Err(rpc_error(
                    LegacyCode::InvalidParameter,
                    "height must be >= 0",
                ))
            }
            Some(h) => h,
            None => snapshot.upgrade.tip_height.saturating_add(1),
        };
        let set = db.set(&id, at).ok_or_else(|| {
            rpc_error(
                LegacyCode::InvalidAddressOrKey,
                format!("unknown set {}", display_hex(&id)),
            )
        })?;
        Ok(SetJson::new(&set, at, true))
    }

    async fn vault_list(&self, filter: Option<VaultListFilter>) -> RpcResult<Vec<TemplateOutJson>> {
        let snapshot = self.snapshot().await?;
        let db = Self::db(&snapshot)?;
        let filter = ParsedFilter::new(filter.unwrap_or_default())?;
        let next = snapshot.upgrade.tip_height.saturating_add(1);
        Ok(db
            .template_outputs()
            .iter()
            .filter(|out| filter.admits(out.kind, &out.script))
            .filter_map(|out| TemplateOutJson::new(out, next))
            .collect())
    }

    async fn vault_decodescript(&self, hex: String) -> RpcResult<DecodedScript> {
        let script = parse_hex(&hex, "hex")?;
        Ok(decode_script(&script, &self.network))
    }
}

/// `vault_list`'s filter, parsed as ycash6 parses it.
struct ParsedFilter {
    tag: Option<Tag>,
    set_id: Option<SetId>,
    owner: Option<PqOwner>,
    kind: Option<TemplateKind>,
}

impl ParsedFilter {
    fn new(f: VaultListFilter) -> RpcResult<Self> {
        if f.mine == Some(true) {
            return Err(rpc_error(
                LegacyCode::InvalidParameter,
                "mine needs a wallet, and kogany has none: filter on owner, or ask the wallet",
            ));
        }
        Ok(Self {
            tag: f.tag.as_deref().map(parse_tag).transpose()?,
            set_id: f
                .setid
                .as_deref()
                .map(|s| parse_display_hash(s, "setid"))
                .transpose()?,
            owner: f.owner.as_deref().map(parse_pqkeyid).transpose()?,
            kind: match f.kind.as_deref() {
                None => None,
                Some("vault") => Some(TemplateKind::Vault),
                Some("intent") => Some(TemplateKind::Intent),
                Some(_) => {
                    return Err(rpc_error(
                        LegacyCode::InvalidParameter,
                        "kind must be vault or intent",
                    ))
                }
            },
        })
    }

    /// Whether the output passes; an output whose script is not its kind's template never does.
    fn admits(&self, kind: TemplateKind, script: &[u8]) -> bool {
        let (tag, set_a, set_b, owner) = match kind {
            TemplateKind::Vault => match parse_vault(script) {
                Some(p) => (p.tag, p.set_id, p.cancel_set_id, p.owner),
                None => return false,
            },
            TemplateKind::Intent => match parse_intent(script) {
                Some(p) => (p.tag, p.set_id, p.cancel_set_id, p.owner),
                None => return false,
            },
        };
        self.kind.is_none_or(|k| k == kind)
            && self.tag.is_none_or(|t| t == tag)
            && self.set_id.is_none_or(|s| s == set_a || s == set_b)
            && self.owner.is_none_or(|o| o == owner)
    }
}

/// ycash6 `ParseTag`: 8 hex digits, or 1-4 characters zero-padded.
fn parse_tag(s: &str) -> RpcResult<Tag> {
    let mut tag = [0u8; 4];
    if s.len() == 8 {
        if let Ok(bytes) = hex::decode(s) {
            tag.copy_from_slice(&bytes);
            return Ok(Tag(tag));
        }
    }
    if s.is_empty() || s.len() > 4 {
        return Err(rpc_error(
            LegacyCode::InvalidParameter,
            "tag must be 1-4 ASCII characters (zero-padded) or 8 hex digits",
        ));
    }
    for (slot, byte) in tag.iter_mut().zip(s.bytes()) {
        *slot = byte;
    }
    Ok(Tag(tag))
}

/// ycash6 `ParsePQKeyId`, its pqkeyid form only: the PQ address forms (`yb…`, `sq…`) need the
/// Ycash address codecs, which kogany does not have yet (plan W1-Y6, W7-b).
fn parse_pqkeyid(s: &str) -> RpcResult<PqOwner> {
    let bytes = match hex::decode(s) {
        Ok(bytes) if bytes.len() == 33 => bytes,
        _ => {
            return Err(rpc_error(
                LegacyCode::InvalidParameter,
                "owner must be a pqkeyid (66 hex digits, scheme || keyhash); PQ addresses are not supported by kogany yet",
            ))
        }
    };
    let (scheme, hash) = bytes.split_at(1);
    let owner = PqOwner {
        scheme: scheme.first().copied().unwrap_or_default(),
        hash: Hash32::from_slice(hash).unwrap_or_default(),
    };
    if !is_known_pq_scheme(owner.scheme) {
        return Err(rpc_error(
            LegacyCode::InvalidParameter,
            "owner: unregistered post-quantum scheme",
        ));
    }
    Ok(owner)
}

/// `vault_decodescript`'s decision, in ycash6's order: V, I, a malformed V or I, a `YV` act,
/// a bond redeem script, none.
pub fn decode_script(script: &[u8], network: &Network) -> DecodedScript {
    let vault = match_vault(script);
    let intent = match_intent(script);
    if let Shape::Match(p) = vault {
        return DecodedScript::Vault(VaultFieldsJson::from(&p));
    }
    if let Shape::Match(p) = intent {
        return DecodedScript::Intent(IntentFieldsJson::from(&p));
    }
    if vault == Shape::Malformed || intent == Shape::Malformed {
        return DecodedScript::Malformed;
    }
    if is_act_output(script) {
        return match decode_act(script) {
            Ok(act) => DecodedScript::Act {
                body: ActBodyJson::from(&act.body),
                signatures: act
                    .sigs
                    .iter()
                    .map(|sig| ActSigJson {
                        sig: raw_hex(&sig.0),
                    })
                    .collect(),
                payload: raw_hex(&encode_payload(&act.body)),
            },
            Err(error) => DecodedScript::ActError {
                error: error.reject_reason(),
            },
        };
    }
    if let Some((locktime, key)) = parse_bond_redeem(script) {
        let p2sh = p2sh_script_pubkey(script);
        let address = transparent::Address::from_script_hash(network.kind(), hash160(script));
        return DecodedScript::Bond {
            locktime,
            memberkey: raw_hex(&key.0),
            scriptpubkey: raw_hex(&p2sh),
            address: address.to_string(),
        };
    }
    DecodedScript::None
}
