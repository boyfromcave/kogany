//! kogany's extension methods (`vault_*`, `set_*`, `yed_*`) as an OpenRPC document, checked
//! against the two RPC contracts (plan docs/plans/kogany W7-d).
//!
//! Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license.
//!
//! The upstream generator (`openrpc.rs`) parses only `RpcServer`; kogany's methods are served
//! beside it by `kogany-rpc` (`zakura_rpc::server::kogany_extension`) and are not in
//! `rpc.discover`. This module writes them to [`ARTIFACT`], from the same sources the
//! `kogany_rpc_trait!` macro reads to build each dispatch's `METHOD_DOCS` and `METHOD_ACCESS`
//! (`crates/kogany-rpc/tests/openrpc_artifact.rs` checks the two agree), and lists the wallet
//! methods kogany does not serve as served by the wallet in front of it, yewd (plan K-3, K-20):
//!
//! - the `yed_*` wallet methods from `YedWalletRefusalDispatch` (kogany answers them `-32601`
//!   with a message naming yewd);
//! - the vault primitive's wallet methods from the vault contract (`"wallet": true`); kogany does
//!   not register them, so they get the server's generic `-32601`.
//!
//! The check then requires the document to cover both contracts (the kogany-local copies
//! `doc/vault-rpc-contract.json` and `doc/yellowback-rpc-contract.json` that the workspace's
//! `make spec` writes, byte-identical to ycash6's): every read method served by kogany, every
//! wallet method served by yewd, no method on both sides and none outside the contracts, and
//! `kogany_rpc::yed::YED_RPC_VERSION` equal to the contract's `rpcversion`.

use std::{collections::BTreeMap, fs, path::Path};

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use quote::ToTokens;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use syn::{
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    FnArg, GenericArgument, ItemTrait, PathArguments, ReturnType, Token, TraitItem, Type,
};

use crate::BoxError;

/// The crate whose presence turns this module on.
pub(super) const RPC_CRATE: &str = "crates/kogany-rpc";
/// The checked-in document.
pub(super) const ARTIFACT: &str = "doc/kogany-rpc-openrpc.json";
/// Its file name in the generator's output directory.
pub(super) const FILE_NAME: &str = "kogany-rpc-openrpc.json";

/// The `kogany_rpc_trait!` sources served by kogany, in document order.
const SERVED_SOURCES: &[&str] = &[
    "crates/kogany-rpc/src/vault.rs",
    "crates/kogany-rpc/src/yed/rpc.rs",
];
/// The `yed_*` wallet refusals (a `macro_rules!` template over a name table).
const WALLET_SOURCE: &str = "crates/kogany-rpc/src/yed/wallet.rs";
/// Where `YED_RPC_VERSION` is defined.
const YED_MOD_SOURCE: &str = "crates/kogany-rpc/src/yed/mod.rs";
const VAULT_CONTRACT: &str = "doc/vault-rpc-contract.json";
const YED_CONTRACT: &str = "doc/yellowback-rpc-contract.json";

const OPENRPC_VERSION: &str = "1.3.2";
const SERVED_BY_KOGANY: &str = "kogany";
const SERVED_BY_SIDECAR: &str = "yewd";

/// Whether this tree carries kogany's RPC crate.
pub(super) fn present(repo_root: &Path) -> bool {
    repo_root.join(RPC_CRATE).is_dir()
}

/// One method of the document.
struct Method {
    name: String,
    description: String,
    /// The access class kogany registers it under; `None` for a method kogany does not register.
    access: Option<String>,
    trait_name: Option<String>,
    served_by: &'static str,
    refusal: Option<&'static str>,
    params: Vec<Value>,
    result: Value,
}

impl Method {
    fn to_json(&self) -> Value {
        let mut method = Map::new();
        method.insert("name".into(), self.name.clone().into());
        method.insert("summary".into(), summary(&self.description).into());
        method.insert("description".into(), self.description.clone().into());
        method.insert("params".into(), Value::Array(self.params.clone()));
        method.insert("result".into(), self.result.clone());
        method.insert("x-kogany-served-by".into(), self.served_by.into());
        if let Some(access) = &self.access {
            method.insert("x-kogany-access".into(), access.clone().into());
        }
        if let Some(trait_name) = &self.trait_name {
            method.insert("x-kogany-trait".into(), trait_name.clone().into());
        }
        if let Some(refusal) = self.refusal {
            method.insert("x-kogany-refusal".into(), refusal.into());
        }
        Value::Object(method)
    }
}

/// The body of a `kogany_rpc_trait!` call: a trait, then `dispatch = Name;`.
struct TraitMacroBody {
    item: ItemTrait,
}

impl Parse for TraitMacroBody {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let item: ItemTrait = input.parse()?;
        let keyword: syn::Ident = input.parse()?;
        if keyword != "dispatch" {
            return Err(syn::Error::new(
                keyword.span(),
                "expected `dispatch = Name;`",
            ));
        }
        input.parse::<Token![=]>()?;
        input.parse::<syn::Ident>()?;
        input.parse::<Token![;]>()?;
        Ok(Self { item })
    }
}

/// One `"name" => ident` entry of the `wallet_methods!` table.
struct WalletEntry {
    name: syn::LitStr,
}

impl Parse for WalletEntry {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name = input.parse()?;
        input.parse::<Token![=>]>()?;
        input.parse::<syn::Ident>()?;
        Ok(Self { name })
    }
}

/// Writes [`FILE_NAME`] to `output_dir`.
pub(super) fn generate(repo_root: &Path, output_dir: &Path) -> Result<(), BoxError> {
    let vault_contract = read_contract(repo_root, VAULT_CONTRACT)?;
    let yed_contract = read_contract(repo_root, YED_CONTRACT)?;
    let rpcversion = yed_contract
        .1
        .get("rpcversion")
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("{YED_CONTRACT} has no integer rpcversion"))?;

    let mut methods = Vec::new();
    for source in SERVED_SOURCES {
        methods.extend(served_methods(&repo_root.join(source))?);
    }
    methods.extend(wallet_refusals(&repo_root.join(WALLET_SOURCE))?);
    methods.extend(vault_wallet_methods(&vault_contract.1)?);

    let document = json!({
        "openrpc": OPENRPC_VERSION,
        "info": {
            "title": "kogany-rpc",
            "description": "kogany's JSON-RPC methods for the vault primitive and Yellowback \
                (vault_*, set_*, yed_*), served beside Zakura's RpcServer, and the wallet methods \
                of the two contracts, which the wallet in front of kogany (yewd) serves. \
                Generated by `cargo xtask generate-rpc-artifacts`; do not edit.",
            "version": format!("rpcversion {rpcversion}"),
        },
        "x-kogany": {
            "rpcversion": rpcversion,
            "sources": SERVED_SOURCES.iter().chain([WALLET_SOURCE].iter()).collect::<Vec<_>>(),
            "contracts": {
                VAULT_CONTRACT: { "sha256": vault_contract.0 },
                YED_CONTRACT: { "sha256": yed_contract.0 },
            },
        },
        "methods": methods.iter().map(Method::to_json).collect::<Vec<_>>(),
    });
    let mut text = serde_json::to_string_pretty(&sorted_keys(document))?;
    text.push('\n');
    fs::write(output_dir.join(FILE_NAME), text)?;
    Ok(())
}

/// ycashd stock methods (in neither contract) kogany serves through its extension because they
/// read the YED index: `verifychain` re-checks the index against the best chain.
const STOCK_METHODS: &[&str] = &["verifychain"];

/// Checks the document in `output_dir` against both contracts and `YED_RPC_VERSION`; prints a
/// one-line summary.
pub(super) fn check_contracts(repo_root: &Path, output_dir: &Path) -> Result<(), BoxError> {
    let document: Value = serde_json::from_str(&fs::read_to_string(output_dir.join(FILE_NAME))?)?;
    let (_, vault_contract) = read_contract(repo_root, VAULT_CONTRACT)?;
    let (_, yed_contract) = read_contract(repo_root, YED_CONTRACT)?;

    let mut served: BTreeMap<String, &str> = BTreeMap::new();
    for method in document["methods"]
        .as_array()
        .ok_or("document has no methods")?
    {
        let name = method["name"].as_str().ok_or("method without a name")?;
        let by = method["x-kogany-served-by"]
            .as_str()
            .ok_or("method without x-kogany-served-by")?;
        if served.insert(name.to_owned(), by).is_some() {
            return Err(format!("{ARTIFACT}: {name} is listed twice").into());
        }
    }

    // contract method -> who must serve it
    let mut expected: BTreeMap<String, (&str, &str)> = BTreeMap::new();
    for (name, method) in vault_contract["methods"]
        .as_object()
        .ok_or_else(|| format!("{VAULT_CONTRACT} has no methods object"))?
    {
        let wallet = method["wallet"]
            .as_bool()
            .ok_or_else(|| format!("{VAULT_CONTRACT}: {name} has no boolean wallet"))?;
        let by = if wallet {
            SERVED_BY_SIDECAR
        } else {
            SERVED_BY_KOGANY
        };
        expected.insert(name.clone(), (by, VAULT_CONTRACT));
    }
    // The yellowback contract has no wallet flag: kogany's YedRpc names the node-context methods,
    // its refusal table the wallet-context ones; each contract command must be on exactly one side.
    let mut problems = Vec::new();
    for name in yed_contract
        .as_object()
        .ok_or_else(|| format!("{YED_CONTRACT} is not an object"))?
        .keys()
        .filter(|key| key.starts_with("yed_"))
    {
        match served.get(name) {
            Some(by) => {
                expected.insert(name.clone(), (by, YED_CONTRACT));
            }
            None => problems.push(format!(
                "{name} ({YED_CONTRACT}) is neither served by kogany nor listed as sidecar-served"
            )),
        }
    }

    for (name, (by, contract)) in &expected {
        match served.get(name) {
            None => problems.push(format!("{name} ({contract}) is not in the document")),
            Some(actual) if actual != by => problems.push(format!(
                "{name} ({contract}) must be served by {by}, the document says {actual}"
            )),
            Some(_) => {}
        }
    }
    for name in served.keys() {
        if STOCK_METHODS.contains(&name.as_str()) {
            continue;
        }
        if !expected.contains_key(name) && !problems.iter().any(|p| p.starts_with(name.as_str())) {
            problems.push(format!("{name} is served but is in neither contract"));
        }
    }

    let rpcversion = yed_contract["rpcversion"].as_i64();
    let constant = yed_rpc_version(&repo_root.join(YED_MOD_SOURCE))?;
    if rpcversion != Some(constant) {
        problems.push(format!(
            "YED_RPC_VERSION is {constant} ({YED_MOD_SOURCE}), {YED_CONTRACT} says {rpcversion:?}"
        ));
    }

    if !problems.is_empty() {
        return Err(format!(
            "kogany OpenRPC document vs the RPC contracts:\n  {}",
            problems.join("\n  ")
        )
        .into());
    }

    let count = |by: &str, contract: &str| {
        expected
            .values()
            .filter(|(b, c)| *b == by && *c == contract)
            .count()
    };
    println!(
        "kogany OpenRPC covers both contracts (rpcversion {constant}): served by kogany {} vault + {} yed, \
         sidecar-served (yewd) {} vault + {} yed",
        count(SERVED_BY_KOGANY, VAULT_CONTRACT),
        count(SERVED_BY_KOGANY, YED_CONTRACT),
        count(SERVED_BY_SIDECAR, VAULT_CONTRACT),
        count(SERVED_BY_SIDECAR, YED_CONTRACT),
    );
    Ok(())
}

/// `value` with every object's keys in sorted order, so the text is the same whether or not the
/// build unifies serde_json's `preserve_order` feature (kogany-rpc enables it).
fn sorted_keys(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted: BTreeMap<String, Value> = object.into_iter().collect();
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(key, value)| (key, sorted_keys(value)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.into_iter().map(sorted_keys).collect()),
        other => other,
    }
}

/// The contract at `path` (relative to the repository) and the SHA-256 of its bytes.
fn read_contract(repo_root: &Path, path: &str) -> Result<(String, Value), BoxError> {
    let bytes = fs::read(repo_root.join(path)).map_err(|error| {
        format!("{path}: {error} (the workspace's `make spec` writes it, a copy of ycash6's)")
    })?;
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok((sha256, serde_json::from_slice(&bytes)?))
}

/// The methods of every `kogany_rpc_trait!` call in `source`, in declaration order.
fn served_methods(source: &Path) -> Result<Vec<Method>, BoxError> {
    let file = syn::parse_file(&fs::read_to_string(source)?)?;
    let mut methods = Vec::new();
    for item in &file.items {
        let syn::Item::Macro(item) = item else {
            continue;
        };
        if !item
            .mac
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "kogany_rpc_trait")
        {
            continue;
        }
        let body: TraitMacroBody = item.mac.parse_body()?;
        let trait_name = body.item.ident.to_string();
        for item in &body.item.items {
            let TraitItem::Fn(method) = item else {
                continue;
            };
            let (name, access) = method_attribute(&method.attrs)?;
            let mut params = Vec::new();
            for input in &method.sig.inputs {
                let FnArg::Typed(input) = input else { continue };
                let syn::Pat::Ident(parameter) = input.pat.as_ref() else {
                    return Err("RPC parameters must have identifier patterns".into());
                };
                let (schema, required) = parameter_schema(&input.ty);
                params.push(json!({
                    "name": parameter.ident.to_string(),
                    "required": required,
                    "schema": schema,
                }));
            }
            methods.push(Method {
                result: json!({
                    "name": format!("{name}_result"),
                    "schema": result_schema(&method.sig.output)?,
                }),
                name,
                description: doc_text(&method.attrs),
                access: Some(access),
                trait_name: Some(trait_name.clone()),
                served_by: SERVED_BY_KOGANY,
                refusal: None,
                params,
            });
        }
    }
    if methods.is_empty() {
        return Err(format!("{}: no kogany_rpc_trait! methods", source.display()).into());
    }
    Ok(methods)
}

/// The `yed_*` wallet refusals: the `wallet_methods!` table's names, with the doc text and access
/// class of the method template in `macro_rules! wallet_methods`.
fn wallet_refusals(source: &Path) -> Result<Vec<Method>, BoxError> {
    let file = syn::parse_file(&fs::read_to_string(source)?)?;
    let mut template = None;
    let mut names = Vec::new();
    for item in &file.items {
        let syn::Item::Macro(item) = item else {
            continue;
        };
        let Some(last) = item.mac.path.segments.last() else {
            continue;
        };
        if last.ident == "macro_rules"
            && item
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "wallet_methods")
        {
            template = find_method_template(item.mac.tokens.clone());
        } else if last.ident == "wallet_methods" {
            let entries = item
                .mac
                .parse_body_with(Punctuated::<WalletEntry, Token![,]>::parse_terminated)?;
            names.extend(entries.into_iter().map(|entry| entry.name.value()));
        }
    }
    let (description, access) = template.ok_or_else(|| {
        format!(
            "{}: no method template in macro_rules! wallet_methods",
            source.display()
        )
    })?;
    if names.is_empty() {
        return Err(format!("{}: empty wallet_methods! table", source.display()).into());
    }
    Ok(names
        .into_iter()
        .map(|name| Method {
            result: json!({ "name": format!("{name}_result"), "schema": {} }),
            name,
            description: description.clone(),
            access: Some(access.clone()),
            trait_name: Some("YedWalletRefusal".into()),
            served_by: SERVED_BY_SIDECAR,
            refusal: Some("-32601 from kogany, naming yewd (YedWalletRefusalDispatch)"),
            params: Vec::new(),
        })
        .collect())
}

/// The doc text and access class of the method in a `macro_rules!` body: the `#[doc = "…"]`
/// attributes right before the `#[method(name = $name, access = Class)]` attribute.
fn find_method_template(tokens: TokenStream) -> Option<(String, String)> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (index, tree) in trees.iter().enumerate() {
        let TokenTree::Group(group) = tree else {
            continue;
        };
        if group.delimiter() == Delimiter::Bracket && index > 0 && is_pound(&trees[index - 1]) {
            let inner: Vec<TokenTree> = group.stream().into_iter().collect();
            if matches!(inner.first(), Some(TokenTree::Ident(ident)) if ident == "method") {
                let access = method_access_tokens(&inner)?;
                let mut docs = Vec::new();
                let mut back = index - 1;
                while back >= 2 {
                    let (TokenTree::Group(doc), true) =
                        (&trees[back - 1], is_pound(&trees[back - 2]))
                    else {
                        break;
                    };
                    match syn::parse2::<syn::MetaNameValue>(doc.stream()) {
                        Ok(value) if value.path.is_ident("doc") => docs.push(value),
                        _ => break,
                    }
                    back -= 2;
                }
                docs.reverse();
                let lines: Vec<String> = docs
                    .iter()
                    .filter_map(|doc| match &doc.value {
                        syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Str(line),
                            ..
                        }) => Some(line.value()),
                        _ => None,
                    })
                    .collect();
                return Some((join_doc_lines(&lines), access));
            }
        }
        if let Some(found) = find_method_template(group.stream()) {
            return Some(found);
        }
    }
    None
}

fn is_pound(tree: &TokenTree) -> bool {
    matches!(tree, TokenTree::Punct(punct) if punct.as_char() == '#')
}

/// `access = Class` inside the tokens of a `method(...)` attribute.
fn method_access_tokens(inner: &[TokenTree]) -> Option<String> {
    let TokenTree::Group(arguments) = inner.get(1)? else {
        return None;
    };
    let arguments: Vec<TokenTree> = arguments.stream().into_iter().collect();
    arguments.windows(3).find_map(|window| match window {
        [TokenTree::Ident(key), TokenTree::Punct(eq), TokenTree::Ident(value)]
            if key == "access" && eq.as_char() == '=' =>
        {
            Some(value.to_string())
        }
        _ => None,
    })
}

/// The vault primitive's wallet methods (`"wallet": true` in the vault contract).
fn vault_wallet_methods(contract: &Value) -> Result<Vec<Method>, BoxError> {
    let methods = contract["methods"]
        .as_object()
        .ok_or_else(|| format!("{VAULT_CONTRACT} has no methods object"))?;
    // By name: the map's iteration order depends on serde_json's `preserve_order` feature.
    let methods: BTreeMap<_, _> = methods.iter().collect();
    Ok(methods
        .into_iter()
        .filter(|(_, method)| method["wallet"].as_bool() == Some(true))
        .map(|(name, method)| Method {
            name: name.clone(),
            description: format!(
                "A vault primitive wallet RPC (`{}`, {VAULT_CONTRACT}), served by yewd (plan K-3, K-20); \
                 kogany does not register it.",
                method["signature"].as_str().unwrap_or(name)
            ),
            access: None,
            trait_name: None,
            served_by: SERVED_BY_SIDECAR,
            refusal: Some("-32601 from kogany, the server's generic Method not found"),
            params: Vec::new(),
            result: json!({ "name": format!("{name}_result"), "schema": {} }),
        })
        .collect())
}

/// `#[method(name = "…", access = Class)]` of a trait method.
fn method_attribute(attrs: &[syn::Attribute]) -> Result<(String, String), BoxError> {
    let attribute = attrs
        .iter()
        .find(|attr| attr.path().is_ident("method"))
        .ok_or("kogany_rpc_trait! methods must have a #[method] attribute")?;
    let (mut name, mut access) = (None, None);
    attribute.parse_nested_meta(|meta| {
        if meta.path.is_ident("name") {
            name = Some(meta.value()?.parse::<syn::LitStr>()?.value());
        } else if meta.path.is_ident("access") {
            access = Some(meta.value()?.parse::<syn::Ident>()?.to_string());
        } else {
            return Err(meta.error("unsupported kogany RPC method attribute"));
        }
        Ok(())
    })?;
    Ok((
        name.ok_or("#[method] must name the method")?,
        access.ok_or("#[method] must give the access class")?,
    ))
}

/// The `///` lines of `attrs`, as the macro's `METHOD_DOCS` holds them after
/// [`join_doc_lines`].
fn doc_text(attrs: &[syn::Attribute]) -> String {
    let lines: Vec<String> = attrs
        .iter()
        .filter(|attr| attr.path().is_ident("doc"))
        .filter_map(|attr| match &attr.meta {
            syn::Meta::NameValue(syn::MetaNameValue {
                value:
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Str(line),
                        ..
                    }),
                ..
            }) => Some(line.value()),
            _ => None,
        })
        .collect();
    join_doc_lines(&lines)
}

/// Doc lines without their leading space, joined by newlines and trimmed: the normal form
/// `crates/kogany-rpc/tests/openrpc_artifact.rs` applies to `METHOD_DOCS` too.
fn join_doc_lines(lines: &[String]) -> String {
    lines
        .iter()
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn summary(description: &str) -> &str {
    description
        .split_once('\n')
        .map_or(description, |(line, _)| line)
}

/// A parameter's JSON Schema and whether it is required (`Option<T>` is not).
fn parameter_schema(ty: &Type) -> (Value, bool) {
    match single_generic(ty, "Option") {
        Some(inner) => (type_schema(inner), false),
        None => (type_schema(ty), true),
    }
}

/// The schema of `T` in a method's `RpcResult<T>`.
fn result_schema(output: &ReturnType) -> Result<Value, BoxError> {
    let ReturnType::Type(_, result) = output else {
        return Err("RPC methods must declare their result type".into());
    };
    let inner = single_generic(result, "RpcResult")
        .ok_or("kogany RPC results must be declared as `RpcResult<T>`")?;
    Ok(type_schema(inner))
}

/// A JSON Schema for the Rust type `ty`: the JSON scalars by name, `Vec<T>` as an array, `Value`
/// as any value, and every other type as an object named by `x-rust-type` (its fields are the
/// contract's, which the contract checks of `crates/kogany-rpc/qa/` hold kogany to).
fn type_schema(ty: &Type) -> Value {
    if let Some(inner) = single_generic(ty, "Vec") {
        return json!({ "type": "array", "items": type_schema(inner) });
    }
    let name = ty.to_token_stream().to_string().replace(' ', "");
    match name.as_str() {
        "String" | "&str" => json!({ "type": "string" }),
        "bool" => json!({ "type": "boolean" }),
        "i32" | "i64" | "u32" | "u64" | "u8" | "u16" | "usize" => json!({ "type": "integer" }),
        "Value" | "serde_json::Value" => json!({}),
        _ => json!({ "type": "object", "x-rust-type": name }),
    }
}

/// `T` when `ty` is `Name<T>`.
fn single_generic<'a>(ty: &'a Type, name: &str) -> Option<&'a Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != name {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    match args.args.first() {
        Some(GenericArgument::Type(inner)) => Some(inner),
        _ => None,
    }
}

/// `pub const YED_RPC_VERSION: i64 = N;` in `source`.
fn yed_rpc_version(source: &Path) -> Result<i64, BoxError> {
    let file = syn::parse_file(&fs::read_to_string(source)?)?;
    for item in &file.items {
        if let syn::Item::Const(item) = item {
            if item.ident == "YED_RPC_VERSION" {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(value),
                    ..
                }) = item.expr.as_ref()
                {
                    return Ok(value.base10_parse()?);
                }
            }
        }
    }
    Err(format!("{}: no integer YED_RPC_VERSION", source.display()).into())
}
