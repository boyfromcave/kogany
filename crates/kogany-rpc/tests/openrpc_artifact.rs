//! The checked-in OpenRPC document of kogany's extension methods (`doc/kogany-rpc-openrpc.json`,
//! written by `cargo xtask generate-rpc-artifacts`, plan W7-d) agrees with what the dispatches
//! register: the names, order, doc text and access class of every `METHOD_DOCS` /
//! `METHOD_ACCESS` entry. xtask parses the sources; this test reads the macro's own output, so
//! the two cannot drift apart.

use kogany_rpc::{
    yed::{YedRpcDispatch, YedWalletRefusalDispatch, WALLET_METHODS},
    VaultRpcDispatch,
};
use serde_json::Value;
use zakura_rpc::server::kogany_extension::ExtensionAccess;

const DOCUMENT: &str = include_str!("../../../doc/kogany-rpc-openrpc.json");

/// The normal form xtask writes (`join_doc_lines`): no leading space, trimmed.
fn normal(doc: &str) -> String {
    doc.lines()
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

fn access_name(access: ExtensionAccess) -> &'static str {
    match access {
        ExtensionAccess::Unauthenticated => "Unauthenticated",
        ExtensionAccess::Admin => "Admin",
        ExtensionAccess::Test => "Test",
    }
}

#[test]
fn document_matches_the_registered_methods() {
    let document: Value = serde_json::from_str(DOCUMENT).expect("the document is JSON");
    let methods = document["methods"].as_array().expect("methods array");

    let registered: Vec<(&str, &str, &str, &str, &str)> = [
        (
            "VaultRpc",
            "kogany",
            VaultRpcDispatch::<()>::METHOD_DOCS,
            VaultRpcDispatch::<()>::METHOD_ACCESS,
        ),
        (
            "YedRpc",
            "kogany",
            YedRpcDispatch::<()>::METHOD_DOCS,
            YedRpcDispatch::<()>::METHOD_ACCESS,
        ),
        (
            "YedWalletRefusal",
            "yewd",
            YedWalletRefusalDispatch::<()>::METHOD_DOCS,
            YedWalletRefusalDispatch::<()>::METHOD_ACCESS,
        ),
    ]
    .into_iter()
    .flat_map(|(trait_name, served_by, docs, access)| {
        assert_eq!(docs.len(), access.len());
        docs.iter()
            .zip(access)
            .map(move |((name, doc), (access_name_, access))| {
                assert_eq!(name, access_name_);
                (*name, *doc, access_name(*access), trait_name, served_by)
            })
    })
    .collect();

    // The document lists the registered methods first, in registration order; then the vault
    // primitive's wallet methods, which kogany does not register.
    assert!(methods.len() > registered.len());
    for (method, (name, doc, access, trait_name, served_by)) in methods.iter().zip(&registered) {
        assert_eq!(method["name"], *name);
        assert_eq!(method["description"], normal(doc), "{name}");
        assert_eq!(method["x-kogany-access"], *access, "{name}");
        assert_eq!(method["x-kogany-trait"], *trait_name, "{name}");
        assert_eq!(method["x-kogany-served-by"], *served_by, "{name}");
    }
    for method in &methods[registered.len()..] {
        let name = method["name"].as_str().expect("a name");
        assert_eq!(method["x-kogany-served-by"], "yewd", "{name}");
        assert!(method.get("x-kogany-access").is_none(), "{name}");
        assert!(
            !registered.iter().any(|entry| entry.0 == name),
            "{name} is registered"
        );
    }

    let refused: Vec<&str> = registered
        .iter()
        .filter(|entry| entry.3 == "YedWalletRefusal")
        .map(|entry| entry.0)
        .collect();
    assert_eq!(refused, WALLET_METHODS);
}
