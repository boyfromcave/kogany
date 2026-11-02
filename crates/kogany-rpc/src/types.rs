//! The result shapes of the vault read RPCs (`ycash6/doc/vault-rpc.md`, "Shapes" and "Read
//! RPCs"), field for field and in ycashd's field order.
//!
//! kogany has no wallet (plan K-3), so the wallet-derived fields are absent: `wallet` on a
//! `Member` and on a `TemplateOut`. The wallet in front of kogany (yewd, plan §3b) adds them.

use kogany_vault::{
    act::{ActBody, SetCreateBody},
    template::{IntentParams, VaultParams},
};
use serde::Serialize;

use crate::{
    json::{display_hex, outpoint_text, pqkeyid_hex, raw_hex, tag_text, Yec},
    state::{MemberView, SetView, TemplateKind, TemplateOutRecord},
};

/// `vault_getinfo`'s result.
#[derive(Clone, Debug, Serialize)]
pub struct VaultInfo {
    /// The Vault branch ID, `"6d5b7a31"`.
    pub branchid: String,
    /// The activation height, -1 when not scheduled.
    pub activationheight: i64,
    /// Whether the upgrade is active at the next block.
    pub active: bool,
    /// The chain tip's height.
    pub height: i64,
    /// The set the registered module governs, null for none.
    pub attestorsetid: Option<String>,
    /// Whether a registered module governs a set on this node.
    pub moduleactive: bool,
    /// The block the set state is at, null before the first active block.
    pub dbtip: Option<DbTipJson>,
    /// The number of sets (absent when the vault database is not open).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sets: Option<u64>,
    /// The number of unspent vault outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vaults: Option<u64>,
    /// The number of unspent intent outputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intents: Option<u64>,
    /// The value the vault outputs hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockedvalue: Option<Yec>,
    /// SHA256d over every state record, display order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statehash: Option<String>,
}

/// `vault_getinfo.dbtip`.
#[derive(Clone, Debug, Serialize)]
pub struct DbTipJson {
    /// The block hash, display order.
    pub hash: String,
    /// The block height.
    pub height: i64,
}

/// The `SetParams` shape.
#[derive(Clone, Debug, Serialize)]
pub struct SetParamsJson {
    seats: u8,
    unlockthreshold: u8,
    cancelthreshold: u8,
    slashthreshold: u8,
    open: bool,
    ratelimitbps: u16,
    ratewindow: u32,
    livenesswindow: u32,
    bondmin: Yec,
    bondlockmin: u32,
    maturity: u32,
    admitkey: String,
}

impl From<&SetCreateBody> for SetParamsJson {
    fn from(c: &SetCreateBody) -> Self {
        Self {
            seats: c.seats,
            unlockthreshold: c.unlock_threshold,
            cancelthreshold: c.cancel_threshold,
            slashthreshold: c.slash_threshold,
            open: c.is_open(),
            ratelimitbps: c.rate_limit_bps,
            ratewindow: c.rate_window,
            livenesswindow: c.liveness_window,
            bondmin: Yec(c.bond_min),
            bondlockmin: c.bond_lock_min,
            maturity: c.maturity,
            admitkey: raw_hex(&c.admit_key.0),
        }
    }
}

/// The `Set` shape (`set_list`), and with `memberlist` the result of `set_getinfo`.
#[derive(Clone, Debug, Serialize)]
pub struct SetJson {
    setid: String,
    height: i64,
    #[serde(flatten)]
    params: SetParamsJson,
    createheight: i64,
    winddownheight: i64,
    lockedvalue: Yec,
    epoch: i64,
    epochbasis: Yec,
    epochused: Yec,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlockavailable: Option<Yec>,
    members: u64,
    active: i64,
    current: i64,
    dormant: bool,
    released: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    memberlist: Option<Vec<MemberJson>>,
}

impl SetJson {
    /// The set evaluated at `height`, with its member list when `with_members`.
    pub fn new(set: &SetView, height: i64, with_members: bool) -> Self {
        Self {
            setid: display_hex(&set.id),
            height,
            params: SetParamsJson::from(&set.params),
            createheight: set.create_height,
            winddownheight: set.winddown_height,
            lockedvalue: Yec(set.locked_value),
            epoch: set.epoch,
            epochbasis: Yec(set.epoch_basis),
            epochused: Yec(set.epoch_used),
            unlockavailable: set.unlock_available.map(Yec),
            // A set has at most 15 seats' worth of members per ApplyTx, so the count fits.
            members: set.members.len() as u64,
            active: set.active,
            current: set.current,
            dormant: set.dormant,
            released: set.released,
            memberlist: with_members.then(|| {
                set.members
                    .iter()
                    .map(|m| MemberJson::new(m, set.params.maturity))
                    .collect()
            }),
        }
    }
}

/// The `Member` shape, without `wallet` (no wallet in kogany).
#[derive(Clone, Debug, Serialize)]
pub struct MemberJson {
    key: String,
    status: &'static str,
    current: bool,
    live: bool,
    joinheight: i64,
    lastact: i64,
    bondoutpoint: String,
    bondvalue: Yec,
    bondlocktime: u32,
    bondfrozen: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exitheight: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unlockheight: Option<i64>,
}

impl MemberJson {
    fn new(m: &MemberView, maturity: u32) -> Self {
        Self {
            key: raw_hex(&m.key.0),
            status: m.status.name(),
            current: m.current,
            live: m.live,
            joinheight: m.join_height,
            lastact: m.last_act,
            bondoutpoint: outpoint_text(&m.bond_outpoint),
            bondvalue: Yec(m.bond_value),
            bondlocktime: m.bond_locktime,
            bondfrozen: m.bond_frozen,
            exitheight: m.exit_height,
            unlockheight: m.exit_height.map(|h| h.saturating_add(i64::from(maturity))),
        }
    }
}

/// The `VaultFields` shape.
#[derive(Clone, Debug, Serialize)]
pub struct VaultFieldsJson {
    tag: String,
    tagtext: String,
    setid: String,
    cancelsetid: String,
    delay: i64,
    ownerheight: i64,
    appheight: i64,
    owner: String,
    ownerscheme: u8,
}

impl From<&VaultParams> for VaultFieldsJson {
    fn from(p: &VaultParams) -> Self {
        Self {
            tag: raw_hex(&p.tag.0),
            tagtext: tag_text(&p.tag),
            setid: display_hex(&p.set_id),
            cancelsetid: display_hex(&p.cancel_set_id),
            delay: p.delay,
            ownerheight: p.owner_height,
            appheight: p.app_height,
            owner: pqkeyid_hex(&p.owner),
            ownerscheme: p.owner.scheme,
        }
    }
}

/// The `IntentFields` shape.
#[derive(Clone, Debug, Serialize)]
pub struct IntentFieldsJson {
    tag: String,
    tagtext: String,
    setid: String,
    cancelsetid: String,
    delay: i64,
    owner: String,
    ownerscheme: u8,
    recipienthash: String,
    vaulthash: String,
}

impl From<&IntentParams> for IntentFieldsJson {
    fn from(p: &IntentParams) -> Self {
        Self {
            tag: raw_hex(&p.tag.0),
            tagtext: tag_text(&p.tag),
            setid: display_hex(&p.set_id),
            cancelsetid: display_hex(&p.cancel_set_id),
            delay: p.delay,
            owner: pqkeyid_hex(&p.owner),
            ownerscheme: p.owner.scheme,
            recipienthash: raw_hex(&p.recipient_hash.0),
            vaulthash: raw_hex(&p.vault_hash.0),
        }
    }
}

/// The fields of a `TemplateOut` that its script gives.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum TemplateOutFields {
    /// A vault's.
    Vault(VaultFieldsJson),
    /// An intent's, with the maturity predicates at the next block and the origin vault script.
    Intent {
        /// The script's fields.
        #[serde(flatten)]
        fields: IntentFieldsJson,
        /// `height + delay`.
        matureheight: i64,
        /// Whether the intent is mature at the next block.
        mature: bool,
        /// Whether a cancel is still possible at the next block.
        cancellable: bool,
        /// The script of the vault it was unlocked from.
        origin: String,
    },
}

/// The `TemplateOut` shape (`vault_list`), without `wallet` (no wallet in kogany).
#[derive(Clone, Debug, Serialize)]
pub struct TemplateOutJson {
    txid: String,
    vout: u32,
    outpoint: String,
    kind: &'static str,
    value: Yec,
    valuezat: i64,
    height: i64,
    script: String,
    #[serde(flatten)]
    fields: TemplateOutFields,
}

impl TemplateOutJson {
    /// The entry `rec` with its predicates at `next` (the next block), or `None` when its script
    /// is not the template its kind says (ycash6 `vault_list` skips such an entry).
    pub fn new(rec: &TemplateOutRecord, next: i64) -> Option<Self> {
        let fields = match rec.kind {
            TemplateKind::Vault => TemplateOutFields::Vault(VaultFieldsJson::from(
                &kogany_vault::template::parse_vault(&rec.script)?,
            )),
            TemplateKind::Intent => {
                let p = kogany_vault::template::parse_intent(&rec.script)?;
                let mature_height = rec.height.saturating_add(p.delay);
                TemplateOutFields::Intent {
                    fields: IntentFieldsJson::from(&p),
                    matureheight: mature_height,
                    mature: next >= mature_height,
                    cancellable: next.saturating_sub(rec.height) < p.delay,
                    origin: raw_hex(&rec.origin),
                }
            }
        };
        Some(Self {
            txid: display_hex(&rec.outpoint.txid),
            vout: rec.outpoint.n,
            outpoint: outpoint_text(&rec.outpoint),
            kind: match rec.kind {
                TemplateKind::Vault => "vault",
                TemplateKind::Intent => "intent",
            },
            value: Yec(rec.value),
            valuezat: rec.value,
            height: rec.height,
            script: raw_hex(&rec.script),
            fields,
        })
    }
}

/// An act body in the `ActBody` shape (its type as `acttype`).
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ActBodyJson {
    /// `SET_CREATE`.
    Create {
        /// `"create"`.
        acttype: &'static str,
        /// The parameters.
        #[serde(flatten)]
        params: SetParamsJson,
    },
    /// `SET_JOIN`.
    Join {
        /// `"join"`.
        acttype: &'static str,
        /// The set.
        setid: String,
        /// The joining key.
        memberkey: String,
        /// The bond's locktime.
        bondlocktime: u32,
        /// The bond's output index.
        bondvout: u8,
    },
    /// `SET_HEARTBEAT`.
    Heartbeat {
        /// `"heartbeat"`.
        acttype: &'static str,
        /// The set.
        setid: String,
        /// The member.
        memberkey: String,
    },
    /// `SET_REMOVE`.
    Remove {
        /// `"remove"`.
        acttype: &'static str,
        /// The set.
        setid: String,
        /// The member.
        memberkey: String,
        /// 1 burns the bond.
        burn: u8,
    },
    /// `SET_EQUIVOCATION`.
    Equivocation {
        /// `"equivocation"`.
        acttype: &'static str,
        /// The set.
        setid: String,
        /// The template input both signatures sign.
        prevout: String,
        /// The first role.
        rolea: u8,
        /// The first sighash.
        sighasha: String,
        /// The first signature.
        siga: String,
        /// The second role.
        roleb: u8,
        /// The second sighash.
        sighashb: String,
        /// The second signature.
        sigb: String,
    },
    /// `SET_WINDDOWN`.
    WindDown {
        /// `"winddown"`.
        acttype: &'static str,
        /// The set.
        setid: String,
    },
}

impl From<&ActBody> for ActBodyJson {
    fn from(body: &ActBody) -> Self {
        match body {
            ActBody::Create(c) => ActBodyJson::Create {
                acttype: "create",
                params: SetParamsJson::from(c),
            },
            ActBody::Join(j) => ActBodyJson::Join {
                acttype: "join",
                setid: display_hex(&j.set_id),
                memberkey: raw_hex(&j.member_key.0),
                bondlocktime: j.bond_locktime,
                bondvout: j.bond_vout,
            },
            ActBody::Heartbeat(h) => ActBodyJson::Heartbeat {
                acttype: "heartbeat",
                setid: display_hex(&h.set_id),
                memberkey: raw_hex(&h.member_key.0),
            },
            ActBody::Remove(r) => ActBodyJson::Remove {
                acttype: "remove",
                setid: display_hex(&r.set_id),
                memberkey: raw_hex(&r.member_key.0),
                burn: r.burn,
            },
            ActBody::Equivocation(e) => ActBodyJson::Equivocation {
                acttype: "equivocation",
                setid: display_hex(&e.set_id),
                prevout: outpoint_text(&e.prevout),
                rolea: e.role_a,
                sighasha: raw_hex(&e.sighash_a.0),
                siga: raw_hex(&e.sig_a.0),
                roleb: e.role_b,
                sighashb: raw_hex(&e.sighash_b.0),
                sigb: raw_hex(&e.sig_b.0),
            },
            ActBody::WindDown(w) => ActBodyJson::WindDown {
                acttype: "winddown",
                setid: display_hex(&w.set_id),
            },
        }
    }
}

/// One act signature (no recovered key: `vault_decodescript` has no spending input).
#[derive(Clone, Debug, Serialize)]
pub struct ActSigJson {
    /// The 65-byte recoverable signature.
    pub sig: String,
}

/// `vault_decodescript`'s result.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DecodedScript {
    /// A vault V scriptPubKey.
    Vault(VaultFieldsJson),
    /// An intent I scriptPubKey.
    Intent(IntentFieldsJson),
    /// A template skeleton with a non-minimal push or an out-of-range field.
    Malformed,
    /// A `YV` act that decodes.
    Act {
        /// The body.
        #[serde(flatten)]
        body: ActBodyJson,
        /// The signatures.
        signatures: Vec<ActSigJson>,
        /// The act payload.
        payload: String,
    },
    /// A `YV` act that does not decode.
    #[serde(rename = "act")]
    ActError {
        /// The reject reason.
        error: &'static str,
    },
    /// A member bond B redeem script.
    Bond {
        /// The CLTV locktime.
        locktime: u32,
        /// The member key.
        memberkey: String,
        /// The P2SH scriptPubKey.
        scriptpubkey: String,
        /// The P2SH address on this network.
        address: String,
    },
    /// Anything else.
    None,
}
