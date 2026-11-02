// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

// The ycash6 side of kogany's vault fuzz verdict replay (qa/fuzz/vault/README.md). Built by
// qa/fuzz/vault/record_verdicts.py against a ycash6 build tree at the pinned commit, never by
// kogany's build. For each input file it prints `<path>\t<verdict>`: the outcome of every parser
// the ycash6 fuzz target of that corpus runs (src/fuzzing/<Target>/fuzz.cpp), as one string of
// `key=value` fields joined by `;`. The Rust side (qa/fuzz/vault/src/verdict.rs) builds the same
// string from kogany's parsers; the replay asserts the two are equal.
//
//   record_verdicts <Vault|YellowbackScript|YellowbackPayload|YellowbackTag> <file>...

#include "crypto/sha256.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "util/strencodings.h"
#include "vault/act.h"
#include "vault/template.h"
#include "yellowback/payload.h"
#include "yellowback/script.h"
#include "yellowback/tag.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

typedef std::vector<unsigned char> valtype;

static std::string Digest(const valtype& v)
{
    unsigned char h[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(v.data(), v.size()).Finalize(h);
    return HexStr(h, h + 8);
}

/** The digest of a list of pushes: SHA256 over each push as u32 LE length || bytes. */
static std::string PushesDigest(const std::vector<valtype>& pushes)
{
    valtype buf;
    for (const valtype& p : pushes) {
        const uint32_t n = p.size();
        for (int i = 0; i < 4; i++) buf.push_back((n >> (8 * i)) & 0xff);
        buf.insert(buf.end(), p.begin(), p.end());
    }
    return Digest(buf);
}

static std::string Dest(const CTxDestination& d)
{
    if (const CKeyID* k = std::get_if<CKeyID>(&d)) return "key:" + HexStr(k->begin(), k->end());
    if (const CScriptID* s = std::get_if<CScriptID>(&d)) return "script:" + HexStr(s->begin(), s->end());
    if (const CPQKeyID* q = std::get_if<CPQKeyID>(&d)) return "pq:" + std::to_string(q->scheme) + ":" + HexStr(q->hash.begin(), q->hash.end());
    return "none";
}

/** Solver's type name and ExtractDestination's destination. */
static std::string ScriptFields(const CScript& s)
{
    txnouttype type;
    std::vector<valtype> sol;
    Solver(s, type, sol);
    CTxDestination d;
    std::string dest = ExtractDestination(s, d) ? Dest(d) : "none";
    return std::string("kind=") + GetTxnOutputType(type) + ";dest=" + dest;
}

static const char* ShapeName(vault::Shape s)
{
    switch (s) {
    case vault::Shape::NONE: return "none";
    case vault::Shape::MATCH: return "match";
    case vault::Shape::MALFORMED: return "malformed";
    }
    return "?";
}

static std::string RunVault(const valtype& data)
{
    using namespace vault;
    // vault_fuzz::Split (src/test/vault_fuzz_harness.h).
    CScript spk, scriptSig;
    if (data.size() < 2) {
        spk = CScript(data.begin(), data.end());
    } else {
        size_t n = (size_t)data[0] | ((size_t)data[1] << 8);
        if (n > data.size() - 2) n = data.size() - 2;
        spk = CScript(data.begin() + 2, data.begin() + 2 + n);
        scriptSig = CScript(data.begin() + 2 + n, data.end());
    }
    std::string r = ScriptFields(spk);
    VaultParams vp;
    IntentParams ip;
    r += std::string(";V=") + ShapeName(MatchVault(spk, vp));
    r += std::string(";I=") + ShapeName(MatchIntent(spk, ip));
    uint32_t locktime;
    CPubKey member;
    r += std::string(";bond=") + (ParseBondRedeem(spk, locktime, member) ? "1" : "0");
    Act act;
    std::optional<std::string> e = DecodeAct(spk, act);
    r += ";act=" + (e ? *e : "ok:" + std::to_string(act.type) + ":" + std::to_string(act.sigs.size()) + ":" + (ActFieldsValid(act) ? "1" : "0"));
    Act bare;
    const valtype P(spk.begin(), spk.end());
    e = DecodePayload(P, bare);
    r += ";P=" + (e ? *e : "ok:" + std::to_string(bare.type) + ":" + (ActFieldsValid(bare) ? "1" : "0"));
    std::vector<valtype> pushes;
    std::optional<uint8_t> sel = ParseSelector(scriptSig, &pushes);
    r += ";sel=" + (sel ? std::to_string(*sel) + ":" + std::to_string(pushes.size()) + ":" + PushesDigest(pushes) : std::string("none"));
    std::optional<TemplateSpend> ts = ParseTemplateSpend(spk, scriptSig);
    r += ";ts=" + (ts ? std::string(ts->kind == TemplateKind::VAULT ? "v:" : "i:") + std::to_string(ts->selector) + ":" + std::to_string(ts->sigs.size()) : std::string("none"));
    return r;
}

static std::string RunYellowbackScript(const valtype& data)
{
    CScript script(data.begin(), data.end());
    std::string r = ScriptFields(script);
    uint32_t lock, claim;
    CPubKey owner;
    r += ";v2=" + (yellowback::ParseVaultScript(script, lock, owner, claim) ? std::to_string(lock) + ":" + std::to_string(claim) : std::string("none"));
    std::optional<yellowback::VaultSpendPath> path = yellowback::ParseVaultSpendPath(script);
    r += ";path=" + (path ? std::string(path->ownerPath ? "1" : "0") + ":" + std::to_string(path->pushes) + ":" + Digest(path->selector) + ":" + Digest(path->ownerSig) : std::string("none"));
    CScript redeem;
    r += ";redeem=" + (yellowback::ExtractRedeemScript(script, redeem) ? std::to_string(redeem.size()) + ":" + Digest(valtype(redeem.begin(), redeem.end())) : std::string("none"));
    std::optional<CTxDestination> holder = yellowback::HolderKey(script);
    r += ";holder=" + (holder ? Dest(*holder) : std::string("none"));
    PQChannelParams cp;
    r += ";chan=" + (MatchPQChannel(script, cp) ? std::to_string(cp.client.scheme) + ":" + std::to_string(cp.refundHeight) : std::string("none"));
    r += std::string(";carrier=") + (yellowback::IsCarrierScript(script) ? "1" : "0");
    CPubKey bpk;
    uint32_t blt;
    r += ";bond=" + (yellowback::ParseBondScript(script, bpk, blt) ? std::to_string(blt) : std::string("none"));
    return r;
}

static std::string RunYellowbackPayload(const valtype& data)
{
    yellowback::Payload p;
    std::string r = "payload=" + (yellowback::DecodePayload(data, p) ? std::to_string((int)p.type) : std::string("none"));
    CScript script = yellowback::PayloadScript(data);
    std::optional<valtype> op = yellowback::ExtractOpReturnData(script);
    r += ";opret=" + (op ? std::to_string(op->size()) : std::string("none"));
    CMutableTransaction mtx;
    mtx.vout.push_back(CTxOut(0, CScript(data.begin(), data.end())));
    mtx.vout.push_back(CTxOut(0, script));
    std::optional<yellowback::FoundPayload> f = yellowback::FindPayload(CTransaction(mtx));
    r += ";found=" + (f ? std::to_string(f->opReturnIndex) + ":" + std::to_string((int)f->payload.type) : std::string("none"));
    r += ";" + ScriptFields(CScript(data.begin(), data.end()));
    return r;
}

static std::string Tag(const std::optional<yellowback::CoinbaseTag>& t)
{
    if (!t) return "none";
    return std::to_string(t->flags) + ":" + std::to_string(t->priceMicroUsd) + ":" + std::to_string(t->sourceMask) + ":" +
           HexStr(t->payoutKey.begin(), t->payoutKey.end());
}

static std::string RunYellowbackTag(const valtype& data)
{
    int nHeight = 1;
    size_t start = 0;
    if (data.size() >= 4) {
        nHeight = (int)(((uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24)) & 0x7FFFFFFF);
        start = 4;
    }
    CScript scriptSig(data.begin() + start, data.end());
    std::string r = "tag=" + Tag(yellowback::FindTag(scriptSig, nHeight));
    r += ";h=";
    for (int h : {0, 1, 16, 17, 65535, 1234567}) {
        r += yellowback::FindTag(CScript(data.begin(), data.end()), h) ? "1" : "0";
    }
    return r;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target> <file>...\n", argv[0]);
        return 2;
    }
    const std::string target = argv[1];
    for (int i = 2; i < argc; i++) {
        std::ifstream f(argv[i], std::ios::binary);
        if (!f) {
            fprintf(stderr, "cannot read %s\n", argv[i]);
            return 2;
        }
        const valtype data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string v;
        if (target == "Vault") v = RunVault(data);
        else if (target == "YellowbackScript") v = RunYellowbackScript(data);
        else if (target == "YellowbackPayload") v = RunYellowbackPayload(data);
        else if (target == "YellowbackTag") v = RunYellowbackTag(data);
        else {
            fprintf(stderr, "unknown target %s\n", target.c_str());
            return 2;
        }
        printf("%s\t%s\n", argv[i], v.c_str());
    }
    return 0;
}
