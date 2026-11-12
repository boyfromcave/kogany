// Copyright (c) 2026 The Ycash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

//! The parameters are **checked against** ycash6's C++ source, never hand-copied without this
//! check (plan W5-a; the module-constant half of the audit's vault-params leg (d)).
//!
//! The test reads `src/yellowback/params.h`, `src/yellowback/params.cpp`, `src/amount.h` and
//! `src/script/script.h` from a ycash6 tree and evaluates them: the `Params::Params()`
//! initialiser list, then each column constructor's statements in order (`SetCommon`,
//! `SetTestnet`, `MainParams`, `TestParams`, `TestFastParams`, `RegtestParams` with its
//! arguments), giving every field of every column. It then requires, column by column, that
//! [`Params::fields`] holds exactly the same fields with exactly the same values, that every
//! namespace constant of `params.h` equals the Rust constant of that name, and that the field list
//! of `struct Params` is the Rust one. Any statement it cannot evaluate fails the test, so a new
//! construct in `params.cpp` is reviewed here rather than skipped.
//!
//! The tree is `$YCASH6_SRC` (the `src` directory), else `../../../ycash6/src` relative to this
//! crate (the main kogany tree's sibling) or `../../../../ycash6/src` (a `wt/` worktree's). If none
//! exists the test is skipped with a message, unless `KOGANY_REQUIRE_YCASH6_SRC=1`, which makes a
//! missing tree a failure (the coordinator's gates set it).

// Test reporting: a gate run shows what was compared.
#![allow(clippy::print_stderr)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kogany_yellowback::params::*;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Val {
    Int(i128),
    Bytes(Vec<u8>),
    Text(String),
}

type Model = BTreeMap<String, Val>;

fn ycash6_src() -> Option<PathBuf> {
    let require = std::env::var("KOGANY_REQUIRE_YCASH6_SRC").is_ok_and(|v| v == "1");
    if let Ok(p) = std::env::var("YCASH6_SRC") {
        let p = PathBuf::from(p);
        assert!(
            p.join("yellowback/params.cpp").is_file(),
            "YCASH6_SRC={} has no yellowback/params.cpp",
            p.display()
        );
        return Some(p);
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for rel in ["../../../ycash6/src", "../../../../ycash6/src"] {
        let p = manifest.join(rel);
        if p.join("yellowback/params.cpp").is_file() {
            return Some(p);
        }
    }
    assert!(
        !require,
        "KOGANY_REQUIRE_YCASH6_SRC=1 but no ycash6 tree: set YCASH6_SRC to ycash6's src directory"
    );
    eprintln!(
        "SKIPPED: params_cpp needs ycash6's source to check the parameters against; set YCASH6_SRC=<ycash6>/src \
         (or KOGANY_REQUIRE_YCASH6_SRC=1 to make its absence a failure)"
    );
    None
}

fn read(src: &Path, rel: &str) -> String {
    let p = src.join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The text with `//` and `/* */` comments removed (string and char literals kept intact).
fn strip_comments(s: &str) -> String {
    let b: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if c == '"' || c == '\'' {
            out.push(c);
            i += 1;
            while i < b.len() && b[i] != c {
                if b[i] == '\\' {
                    out.push(b[i]);
                    i += 1;
                }
                if i < b.len() {
                    out.push(b[i]);
                    i += 1;
                }
            }
            if i < b.len() {
                out.push(b[i]);
                i += 1;
            }
        } else if c == '/' && next == Some('/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            out.push(' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Index of the bracket matching the opening one at `open`.
fn matching(s: &str, open: usize, o: u8, c: u8) -> usize {
    let bytes = s.as_bytes();
    assert_eq!(bytes[open], o);
    let mut depth = 0i32;
    for (i, ch) in bytes.iter().enumerate().skip(open) {
        if *ch == o {
            depth += 1;
        } else if *ch == c {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
    }
    panic!("unbalanced {} at {open}", o as char);
}

/// The text inside the first `{ ... }` after `header`.
fn body_after<'a>(s: &'a str, header: &str) -> &'a str {
    let at = s
        .find(header)
        .unwrap_or_else(|| panic!("`{header}` not found in the C++ source"));
    let open = at + s[at..].find('{').expect("a body");
    let close = matching(s, open, b'{', b'}');
    &s[open + 1..close]
}

/// Collapse runs of whitespace to one space.
fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Remove every `kw( ... )` (balanced) from the text: `assert(...)` and `for (...)` headers.
fn remove_calls(s: &str, kw: &str) -> String {
    let mut out = s.to_string();
    while let Some(at) = find_word(&out, kw) {
        let open = at + out[at..].find('(').expect("a paren after the keyword");
        let close = matching(&out, open, b'(', b')');
        out.replace_range(at..=close, " ");
    }
    out
}

fn find_word(s: &str, kw: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(i) = s[from..].find(kw) {
        let at = from + i;
        let before = s[..at].chars().last();
        let after = s[at + kw.len()..].trim_start().chars().next();
        if !before.is_some_and(|c| c.is_alphanumeric() || c == '_') && after == Some('(') {
            return Some(at);
        }
        from = at + kw.len();
    }
    None
}

/// The C++ evaluation context: the namespace constants and, inside `RegtestParams`, its arguments.
struct Ctx<'a> {
    consts: &'a BTreeMap<String, Val>,
    args: BTreeMap<String, Val>,
}

fn eval_int_term(t: &str, ctx: &Ctx) -> Result<i128, String> {
    let t = t.trim();
    if let Some(neg) = t.strip_prefix('-') {
        return eval_int_term(neg, ctx).map(|v| -v);
    }
    let digits = t.trim_end_matches(['L', 'l', 'U', 'u']);
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        return i128::from_str_radix(hex, 16).map_err(|_| format!("bad hex literal `{t}`"));
    }
    if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
        return digits.parse().map_err(|_| format!("bad literal `{t}`"));
    }
    match t {
        "true" => return Ok(1),
        "false" => return Ok(0),
        "BundleCarrier::SCRIPTSIG" => return Ok(0),
        "BundleCarrier::OP_RETURN" => return Ok(1),
        "BundleCarrier::EITHER" => return Ok(2),
        // crypto/pq/scheme.h
        "pq::SCHEME_SLH_DSA_SHA2_128S" => return Ok(1),
        "pq::SCHEME_FN_DSA_512" => return Ok(2),
        _ => {}
    }
    match ctx.consts.get(t).or_else(|| ctx.args.get(t)) {
        Some(Val::Int(v)) => Ok(*v),
        other => Err(format!("cannot evaluate `{t}` as an integer ({other:?})")),
    }
}

fn try_eval(rhs: &str, ctx: &Ctx) -> Result<Val, String> {
    let rhs = rhs.trim();
    if let Some(s) = rhs.strip_prefix('"') {
        return s
            .strip_suffix('"')
            .map(|s| Val::Text(s.to_string()))
            .ok_or_else(|| format!("open string `{rhs}`"));
    }
    if let Some(list) = rhs.strip_prefix('{') {
        let list = list
            .strip_suffix('}')
            .ok_or_else(|| format!("open brace list `{rhs}`"))?;
        let mut bytes = Vec::new();
        for x in list.split(',').filter(|x| !x.trim().is_empty()) {
            bytes.push(
                u8::try_from(eval_int_term(x, ctx)?).map_err(|_| format!("`{x}` is not a byte"))?,
            );
        }
        return Ok(Val::Bytes(bytes));
    }
    if let Some(Val::Bytes(b)) = ctx.args.get(rhs) {
        return Ok(Val::Bytes(b.clone()));
    }
    let mut product: i128 = 1;
    for t in rhs.split('*') {
        product = product
            .checked_mul(eval_int_term(t, ctx)?)
            .ok_or_else(|| format!("overflow in `{rhs}`"))?;
    }
    Ok(Val::Int(product))
}

fn eval(rhs: &str, ctx: &Ctx) -> Val {
    try_eval(rhs, ctx).unwrap_or_else(|e| panic!("{e}"))
}

/// Runs a constructor's statements on `model`. `Params x` resets it to the defaults;
/// `SetCommon(x)` / `SetTestnet(x)` run those bodies; `x.field = value` assigns. `strict`
/// (the two helpers' bodies) admits assignments only.
fn run(
    body: &str,
    model: &mut Model,
    defaults: &Model,
    helpers: &BTreeMap<&str, String>,
    ctx: &Ctx,
    strict: bool,
) {
    let body = remove_calls(&remove_calls(body, "assert"), "for");
    for stmt in body.split(';') {
        let mut st = squash(stmt);
        if let Some(rest) = st.strip_prefix("static Params p = [] {") {
            st = rest.trim().to_string();
        }
        if st.is_empty() {
            continue;
        }
        if let Some((lhs, rhs)) = split_assignment(&st) {
            let (_, field) = lhs
                .split_once('.')
                .expect("split_assignment returns a member path");
            let field = field.to_string();
            if model.contains_key(&format!("{field}[{}]", PQ_SCHEMES[0])) {
                assign_pq_map(model, &field, rhs, ctx);
                continue;
            }
            assert!(
                model.contains_key(&field),
                "params.cpp assigns `{field}`, which the field model lacks"
            );
            model.insert(field, eval(rhs, ctx));
            continue;
        }
        assert!(!strict, "unexpected statement in a column helper: `{st}`");
        if let Some(name) = st
            .strip_suffix(')')
            .and_then(|s| s.split_once('('))
            .map(|(f, _)| f.trim())
        {
            if let Some(h) = helpers.get(name) {
                run(h, model, defaults, helpers, ctx, true);
                continue;
            }
        }
        if st.starts_with("Params ") && !st.contains('=') {
            *model = defaults.clone();
            continue;
        }
        if st.starts_with("return ") || st == "}()" || st == "static Params p = [] {" {
            continue;
        }
        panic!("params.cpp statement not understood: `{st}`");
    }
}

/// The registered post-quantum schemes (`crypto/pq/scheme.h`), the keys of a version map.
const PQ_SCHEMES: [u8; 2] = [1, 2];

/// `x.pqAddressVersions = { { pq::SCHEME_…, { 0x.., 0x.., 0x.. } }, … }`: every key of the map
/// is set (a key the list lacks is empty, as in a fresh `std::map`); a key outside the registry
/// or named twice fails.
fn assign_pq_map(model: &mut Model, field: &str, rhs: &str, ctx: &Ctx) {
    let body = rhs
        .trim()
        .strip_prefix('{')
        .and_then(|b| b.strip_suffix('}'))
        .unwrap_or_else(|| panic!("{field}: not a brace list: `{rhs}`"));
    let mut set = BTreeMap::new();
    let mut rest = body.trim();
    while !rest.is_empty() {
        let open = rest
            .find('{')
            .unwrap_or_else(|| panic!("{field}: entry expected in `{rest}`"));
        let close = matching(rest, open, b'{', b'}');
        let entry = &rest[open + 1..close];
        let (key, value) = entry
            .split_once(',')
            .unwrap_or_else(|| panic!("{field}: entry `{entry}`"));
        let key = eval_int_term(key, ctx).unwrap_or_else(|e| panic!("{field}: {e}"));
        let key = u8::try_from(key).unwrap_or_else(|_| panic!("{field}: key {key}"));
        assert!(
            PQ_SCHEMES.contains(&key),
            "{field}: unregistered scheme {key}"
        );
        let value = eval(value, ctx);
        assert!(
            set.insert(key, value).is_none(),
            "{field}: scheme {key} twice"
        );
        rest = rest[close + 1..].trim().trim_start_matches(',').trim();
    }
    for scheme in PQ_SCHEMES {
        model.insert(
            format!("{field}[{scheme}]"),
            set.remove(&scheme).unwrap_or(Val::Bytes(Vec::new())),
        );
    }
}

/// `x.field = value` with `x` a one-letter object and `field` a member path (`classMin[0]`,
/// `feeBands[1].bps`); `None` for any other statement.
fn split_assignment(st: &str) -> Option<(&str, &str)> {
    let b = st.as_bytes();
    let i = (0..b.len()).find(|&i| {
        b[i] == b'='
            && b.get(i + 1) != Some(&b'=')
            && (i == 0 || !matches!(b[i - 1], b'=' | b'<' | b'>' | b'!'))
    })?;
    let lhs = st[..i].trim();
    let (var, field) = lhs.split_once('.')?;
    let member = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '[' | ']' | '.');
    if var.len() == 1
        && var.chars().all(|c| c.is_ascii_lowercase())
        && !field.is_empty()
        && field.chars().all(member)
    {
        Some((lhs, &st[i + 1..]))
    } else {
        None
    }
}

/// `static const <type> NAME = value;` at namespace level of a header.
/// `strict` fails on a value it cannot evaluate; otherwise such a constant is left out.
fn header_consts(
    h: &str,
    ctx_consts: &BTreeMap<String, Val>,
    strict: bool,
) -> BTreeMap<String, Val> {
    let mut out = BTreeMap::new();
    let mut consts = ctx_consts.clone();
    for stmt in strip_comments(h).split(';') {
        let st = squash(stmt);
        let Some(pos) = st.find("static const ") else {
            continue;
        };
        let decl = &st[pos + "static const ".len()..];
        let (lhs, rhs) = decl
            .split_once('=')
            .unwrap_or_else(|| panic!("constant without a value: `{st}`"));
        let name = lhs.split_whitespace().last().expect("a name");
        let name = name.split('[').next().expect("a name").to_string();
        let ctx = Ctx {
            consts: &consts,
            args: BTreeMap::new(),
        };
        match try_eval(rhs, &ctx) {
            Ok(v) => {
                consts.insert(name.clone(), v.clone());
                out.insert(name, v);
            }
            Err(e) => assert!(!strict, "params.h constant {name}: {e}"),
        }
    }
    out
}

/// The field names of `struct Params` in declaration order, arrays expanded, with their kind.
fn struct_fields(h: &str) -> Vec<(String, &'static str)> {
    let h = strip_comments(h);
    let fee_band = body_after(&h, "struct FeeBand");
    assert_eq!(
        squash(fee_band),
        "Cents uptoCents; int bps;",
        "struct FeeBand changed"
    );
    let body = body_after(&h, "struct Params");
    // Keep depth-0 text only (drop inline method bodies).
    let mut flat = String::new();
    let mut depth = 0;
    for ch in body.chars() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                flat.push(';');
            }
            _ if depth == 0 => flat.push(ch),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for stmt in flat.split(';') {
        let st = squash(stmt);
        if st.is_empty() || st.contains('(') {
            continue; // methods and the constructor
        }
        let (ty, kind) = [
            // D-9: one 3-byte version per post-quantum scheme, a field per registered scheme.
            ("std::map<uint8_t, std::vector<unsigned char>> ", "pqmap"),
            ("std::vector<unsigned char> ", "bytes"),
            ("std::string ", "text"),
            ("uint256 ", "bytes"),
            ("BundleCarrier ", "int"),
            ("FeeBand ", "band"),
            ("CAmount ", "int"),
            ("Cents ", "int"),
            ("bool ", "int"),
            ("int ", "int"),
        ]
        .into_iter()
        .find(|(t, _)| st.starts_with(t))
        .unwrap_or_else(|| panic!("struct Params member of an unknown type: `{st}`"));
        for name in st[ty.len()..].split(',') {
            let name = name.trim();
            if let Some((base, n)) = name.split_once('[') {
                let n = match n.trim_end_matches(']') {
                    "NUM_CLASSES" => NUM_CLASSES,
                    "FEE_BANDS" => FEE_BANDS,
                    other => panic!("array of unknown size {other}"),
                };
                for i in 0..n {
                    if kind == "band" {
                        out.push((format!("{base}[{i}].uptoCents"), "int"));
                        out.push((format!("{base}[{i}].bps"), "int"));
                    } else {
                        out.push((format!("{base}[{i}]"), kind));
                    }
                }
            } else if kind == "pqmap" {
                for scheme in PQ_SCHEMES {
                    out.push((format!("{name}[{scheme}]"), "bytes"));
                }
            } else {
                assert_ne!(kind, "band", "a scalar FeeBand");
                out.push((name.to_string(), kind));
            }
        }
    }
    out
}

/// `Params::Params()`: the initialiser list, the array loops, and the type defaults.
fn defaults(cpp: &str, fields: &[(String, &'static str)], ctx: &Ctx) -> Model {
    let at = cpp
        .find("Params::Params()")
        .expect("the Params constructor")
        + "Params::Params()".len();
    let colon = at + cpp[at..].find(':').expect("an initialiser list");
    let open = colon + cpp[colon..].find('{').expect("a constructor body");
    let init = &cpp[colon + 1..open];
    let mut model = Model::new();
    for (name, kind) in fields {
        let v = match *kind {
            "bytes" => Val::Bytes(if name == "attestorSetId" {
                vec![0; 32]
            } else {
                Vec::new()
            }),
            "text" => Val::Text(String::new()),
            _ => Val::Int(0),
        };
        model.insert(name.clone(), v);
    }
    let mut initialised = Vec::new();
    for item in init.split("),") {
        let item = squash(item);
        let item = item.trim_end_matches(')');
        let (name, v) = item
            .split_once('(')
            .unwrap_or_else(|| panic!("initialiser `{item}`"));
        let name = name.trim();
        assert!(
            model.contains_key(name),
            "the constructor initialises `{name}`, not a field"
        );
        model.insert(name.to_string(), eval(v, ctx));
        initialised.push(name.to_string());
    }
    let close = matching(cpp, open, b'{', b'}');
    let ctor_body = squash(&cpp[open + 1..close]);
    assert!(
        ctor_body
            .contains("classMin[i] = classMax[i] = baseRatioBps[i] = earlyRedeemFeeBps[i] = 0;")
            && ctor_body.contains("feeBands[i].uptoCents = 0; feeBands[i].bps = 0;"),
        "Params::Params() array initialisation changed: `{ctor_body}`"
    );
    for (name, kind) in fields {
        if *kind == "int" && !name.contains('[') {
            assert!(
                initialised.contains(name),
                "Params::Params() leaves `{name}` uninitialised"
            );
        }
    }
    model
}

fn rust_model(p: &Params) -> Model {
    p.fields()
        .into_iter()
        .map(|(k, v)| {
            let v = match v {
                ParamValue::Int(i) => Val::Int(i.into()),
                ParamValue::Bytes(b) => Val::Bytes(b),
                ParamValue::Text(t) => Val::Text(t.to_string()),
            };
            (k, v)
        })
        .collect()
}

fn compare(column: &str, cpp: &Model, rust: &Model) {
    let mut diffs = Vec::new();
    for (k, v) in cpp {
        match rust.get(k) {
            Some(r) if r == v => {}
            Some(r) => diffs.push(format!("  {k}: params.cpp {v:?}, Rust {r:?}")),
            None => diffs.push(format!("  {k}: in params.cpp, missing in Rust")),
        }
    }
    for k in rust.keys() {
        if !cpp.contains_key(k) {
            diffs.push(format!("  {k}: in Rust, missing in params.cpp"));
        }
    }
    assert!(
        diffs.is_empty(),
        "column {column} differs from ycash6 params.cpp:\n{}",
        diffs.join("\n")
    );
    eprintln!("column {column}: {} fields equal to params.cpp", cpp.len());
}

fn int(v: i128) -> Val {
    Val::Int(v)
}

#[test]
fn params_equal_ycash6_params_cpp() {
    let Some(src) = ycash6_src() else { return };
    eprintln!("checking against {}", src.display());

    // amount.h, script.h
    let mut base = BTreeMap::new();
    for (rel, names) in [
        ("amount.h", &["COIN", "MAX_MONEY"][..]),
        ("script/script.h", &["LOCKTIME_THRESHOLD"][..]),
    ] {
        let consts = header_consts(&read(&src, rel), &base, false);
        for n in names {
            base.insert(
                n.to_string(),
                consts
                    .get(*n)
                    .unwrap_or_else(|| panic!("{rel} lacks {n}"))
                    .clone(),
            );
        }
    }
    assert_eq!(base["COIN"], int(COIN.into()));
    assert_eq!(base["MAX_MONEY"], int(MAX_MONEY.into()));
    assert_eq!(base["LOCKTIME_THRESHOLD"], int(LOCKTIME_THRESHOLD.into()));

    // params.h namespace constants: exactly the Rust ones.
    let h = read(&src, "yellowback/params.h");
    let consts = header_consts(&h, &base, true);
    let rust_consts: BTreeMap<&str, Val> = [
        ("PAYLOAD_MAGIC_0", int(PAYLOAD_MAGIC_0.into())),
        ("PAYLOAD_MAGIC_1", int(PAYLOAD_MAGIC_1.into())),
        ("PAYLOAD_VERSION", int(PAYLOAD_VERSION.into())),
        ("MINT_PAYLOAD_VERSION", int(MINT_PAYLOAD_VERSION.into())),
        ("MAX_PAYLOAD", int(MAX_PAYLOAD as i128)),
        ("MIN_PAYLOAD", int(MIN_PAYLOAD as i128)),
        ("TAG_MAGIC", Val::Bytes(TAG_MAGIC.to_vec())),
        ("TAG_VERSION", int(TAG_VERSION.into())),
        ("TAG_SIZE", int(TAG_SIZE as i128)),
        ("BLOCKS_PER_HOUR", int(BLOCKS_PER_HOUR.into())),
        ("BLOCKS_PER_DAY", int(BLOCKS_PER_DAY.into())),
        ("BLOCKS_PER_YEAR", int(BLOCKS_PER_YEAR.into())),
        ("PRICE_MIN", int(PRICE_MIN.into())),
        ("PRICE_MAX", int(PRICE_MAX.into())),
        ("REF_WINDOW", int(REF_WINDOW.into())),
        ("DEFAULT_REF_LAG", int(DEFAULT_REF_LAG.into())),
        ("MAX_REF_LAG", int(MAX_REF_LAG.into())),
        ("TOKEN_VALUE", int(TOKEN_VALUE.into())),
        ("DEFAULT_YELLOWBACK_FEE", int(DEFAULT_YELLOWBACK_FEE.into())),
        ("NUM_CLASSES", int(NUM_CLASSES as i128)),
        ("TAG_PRICE_SIGNAL_ONLY", int(TAG_PRICE_SIGNAL_ONLY.into())),
        ("FEE_VOUT_NONE", int(FEE_VOUT_NONE.into())),
        ("FEE_BANDS", int(FEE_BANDS as i128)),
    ]
    .into_iter()
    .collect();
    let cpp_names: Vec<&str> = consts.keys().map(String::as_str).collect();
    let rust_names: Vec<&str> = rust_consts.keys().copied().collect();
    assert_eq!(
        cpp_names, rust_names,
        "params.h's constants and the Rust ones are different sets"
    );
    for (k, v) in &rust_consts {
        assert_eq!(&consts[*k], v, "params.h {k}");
    }
    eprintln!("params.h: {} constants equal", consts.len());

    // RegtestParams' default arguments.
    let hs = strip_comments(&h);
    let decl_at = hs
        .find("Params RegtestParams(")
        .expect("RegtestParams declaration");
    let decl_open = decl_at + hs[decl_at..].find('(').expect("(");
    let decl = squash(&hs[decl_open + 1..matching(&hs, decl_open, b'(', b')')]);
    let mut all = base.clone();
    all.extend(consts.clone());
    let ctx0 = Ctx {
        consts: &all,
        args: BTreeMap::new(),
    };
    let mut header_defaults = BTreeMap::new();
    for p in decl.split(',') {
        if let Some((lhs, v)) = p.split_once('=') {
            let name = lhs
                .split_whitespace()
                .last()
                .expect("a parameter name")
                .to_string();
            header_defaults.insert(name, eval(v, &ctx0));
        }
    }
    assert_eq!(
        header_defaults,
        BTreeMap::from([
            (
                "attestArmMin".to_string(),
                int(REGTEST_DEFAULT_ATTEST_ARM_MIN.into())
            ),
            (
                "bundleCarrier".to_string(),
                int((REGTEST_DEFAULT_BUNDLE_CARRIER as u8).into())
            ),
            (
                "mintRequiresArmed".to_string(),
                int(REGTEST_DEFAULT_MINT_REQUIRES_ARMED.into())
            ),
        ]),
        "RegtestParams' default arguments"
    );

    // struct Params: the same fields.
    let fields = struct_fields(&h);
    let rust_fields: Vec<String> = Params::default()
        .fields()
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    let mut a: Vec<&String> = fields.iter().map(|(k, _)| k).collect();
    let mut b: Vec<&String> = rust_fields.iter().collect();
    a.sort();
    b.sort();
    assert_eq!(
        a, b,
        "struct Params and Params::fields() list different fields"
    );
    eprintln!("struct Params: {} fields", fields.len());

    // params.cpp: evaluate every column.
    let cpp = strip_comments(&read(&src, "yellowback/params.cpp"));
    let defaults = defaults(&cpp, &fields, &ctx0);
    compare("Params()", &defaults, &rust_model(&Params::default()));
    let helpers: BTreeMap<&str, String> = BTreeMap::from([
        (
            "SetCommon",
            body_after(&cpp, "void SetCommon(Params& p)").to_string(),
        ),
        (
            "SetTestnet",
            body_after(&cpp, "void SetTestnet(Params& t)").to_string(),
        ),
    ]);
    let column = |header: &str, ctx: &Ctx| -> Model {
        let mut m = defaults.clone();
        run(
            body_after(&cpp, header),
            &mut m,
            &defaults,
            &helpers,
            ctx,
            false,
        );
        m
    };
    compare(
        "main",
        &column("const Params& MainParams()", &ctx0),
        &rust_model(&main_params()),
    );
    compare(
        "test",
        &column("const Params& TestParams()", &ctx0),
        &rust_model(&test_params()),
    );
    compare(
        "test-fast",
        &column("const Params& TestFastParams()", &ctx0),
        &rust_model(&test_fast_params()),
    );

    // RegtestParams(...): bind the arguments by position.
    let def_at = cpp
        .find("Params RegtestParams(")
        .expect("RegtestParams definition");
    let def_open = def_at + cpp[def_at..].find('(').expect("(");
    let sig = squash(&cpp[def_open + 1..matching(&cpp, def_open, b'(', b')')]);
    let arg_names: Vec<String> = sig
        .split(',')
        .map(|p| {
            p.split_whitespace()
                .last()
                .expect("a parameter")
                .trim_start_matches('&')
                .to_string()
        })
        .collect();
    assert_eq!(
        arg_names.len(),
        7,
        "RegtestParams takes seven arguments: {sig}"
    );
    let set: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    for (args, rust) in [
        (
            vec![
                int(150),
                int(12345),
                int(700),
                Val::Bytes(set.to_vec()),
                int(0),
                int(2),
                int(1),
            ],
            regtest_params_with(150, 12345, 700, set, 0, BundleCarrier::Either, true),
        ),
        (
            vec![
                int(7),
                int(0),
                int(0),
                Val::Bytes(set.to_vec()),
                int(5),
                int(1),
                int(0),
            ],
            regtest_params_with(7, 0, 0, set, 5, BundleCarrier::OpReturn, false),
        ),
        (
            vec![
                int(0),
                int(0),
                int(0),
                Val::Bytes(vec![0; 32]),
                int(3),
                int(0),
                int(0),
            ],
            regtest_params(0, 0, 0, [0; 32]),
        ),
    ] {
        let ctx = Ctx {
            consts: &all,
            args: arg_names.iter().cloned().zip(args).collect(),
        };
        compare(
            "regtest",
            &column("Params RegtestParams(", &ctx),
            &rust_model(&rust),
        );
    }

    // ParamsForNetwork's table.
    let pfn = squash(body_after(
        &cpp,
        "const Params& ParamsForNetwork(const std::string& networkId)",
    ));
    for needle in [
        r#"if (networkId == "main") return MainParams();"#,
        r#"if (networkId == "test") return TestParams();"#,
        r#"static Params r = RegtestParams(0, 0, 0, uint256());"#,
    ] {
        assert!(
            pfn.contains(needle),
            "ParamsForNetwork changed: missing `{needle}` in `{pfn}`"
        );
    }
    assert_eq!(
        params_for_network("regtest"),
        Some(regtest_params(0, 0, 0, [0; 32]))
    );
}
