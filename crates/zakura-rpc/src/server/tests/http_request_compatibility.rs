//! Tests for the HTTP request compatibility middleware.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::Frame;
use tower::{BoxError, Service};

use crate::server::{
    http::{HttpBody, HttpRequest, HttpResponse},
    http_request_compatibility::HttpRequestMiddleware,
};

/// A body that always returns an error, simulating a TCP RST during body collection.
struct ErrorBody;

impl http_body::Body for ErrorBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err("connection reset".into())))
    }
}

/// A mock inner service that returns a minimal JSON-RPC 2.0 response.
#[derive(Clone)]
struct MockRpcService;

impl Service<HttpRequest> for MockRpcService {
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: HttpRequest) -> Self::Future {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":null}"#;
        let response = HttpResponse::new(HttpBody::from(body.to_string()));
        Box::pin(async { Ok(response) })
    }
}

/// Verifies that body collection errors return `Err` instead of panicking.
///
/// Previously, the middleware called `.expect()` on `body.collect().await`,
/// so a TCP RST during body reading would panic the process.
#[tokio::test]
async fn request_body_error_returns_err_instead_of_panic() {
    let request = HttpRequest::builder()
        .method("POST")
        .header("content-type", "appliion/json")
        .body(ErrorBody)
        .expect("valid request");

    let mut middleware = HttpRequestMiddleware::new(MockRpcService, None, 2_097_152);
    let result = middleware.call(request).await;

    assert!(
        result.is_err(),
        "body collection error should return Err, not panic"
    );
}

/// Verifies that a request body exceeding `max_request_body_size` is rejected.
#[tokio::test]
async fn oversized_request_body_is_rejected() {
    let limit = 64;
    let oversized = vec![b'x'; limit + 1];
    let body = HttpBody::from(oversized);
    let request = HttpRequest::builder()
        .method("POST")
        .header("content-type", "application/json")
        .body(body)
        .expect("valid request");

    let mut middleware = HttpRequestMiddleware::new(MockRpcService, None, limit);
    let result = middleware.call(request).await;

    assert!(result.is_err(), "oversized request body should be rejected");
}

/// An inner service that parses the forwarded body as the JSON-RPC server does, and answers
/// `"ok"` for a call to a method with no parameters, else `-32600`.
#[cfg(feature = "ycash")]
#[derive(Clone)]
struct ParsingRpcService;

#[cfg(feature = "ycash")]
impl Service<HttpRequest> for ParsingRpcService {
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: HttpRequest) -> Self::Future {
        Box::pin(async move {
            use http_body_util::BodyExt;
            let bytes = req.into_body().collect().await?.to_bytes();
            let body = match crate::server::jsonrpc::Body::parse(&bytes, true, 10) {
                crate::server::jsonrpc::Body::Call(request)
                    if request.method_name() == "getblockcount"
                        && matches!(
                            request.params().sequence().optional_next::<u32>(),
                            Ok(None)
                        ) =>
                {
                    r#"{"jsonrpc":"2.0","id":"yindex","result":"ok"}"#
                }
                _ => {
                    r#"{"jsonrpc":"2.0","id":"yindex","error":{"code":-32600,"message":"Invalid request"}}"#
                }
            };
            Ok(HttpResponse::new(HttpBody::from(body.to_string())))
        })
    }
}

/// Ycash (S5, yindex): ycashd takes a JSON-RPC 1.0 request whose `params` is `null`, absent or
/// `[]` alike; kogany forwards all three as a call with no parameters.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_one_point_zero_null_absent_and_empty_params_are_no_arguments() {
    use http_body_util::BodyExt;
    for body in [
        r#"{"jsonrpc":"1.0","id":"yindex","method":"getblockcount","params":null}"#,
        r#"{"jsonrpc":"1.0","id":"yindex","method":"getblockcount"}"#,
        r#"{"jsonrpc":"1.0","id":"yindex","method":"getblockcount","params":[]}"#,
        r#"{"id":"yindex","method":"getblockcount","params":null}"#,
        r#"{"id":"yindex","method":"getblockcount"}"#,
    ] {
        let request = HttpRequest::builder()
            .method("POST")
            .header("content-type", "application/json")
            .body(HttpBody::from(body.to_owned()))
            .expect("valid request");
        let mut middleware = HttpRequestMiddleware::new(ParsingRpcService, None, 2_097_152);
        let response = middleware.call(request).await.expect("a response");
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(json["result"], "ok", "{body}: {json}");
        assert_eq!(json["error"], serde_json::Value::Null, "{body}: {json}");
    }
}

/// Ycash (beta3 item 7): an RPC service for batch tests. It answers a call with its method and
/// parameters, `nosuchmethod` with `Method not found`, and `getblock` past the tip with ycashd's
/// `Block height out of range`.
#[cfg(feature = "ycash")]
#[derive(Clone)]
struct EchoRpc;

#[cfg(feature = "ycash")]
impl crate::server::rpc_service::RpcServiceT for EchoRpc {
    fn call<'a>(
        &self,
        request: crate::server::jsonrpc::Request<'a>,
    ) -> impl Future<Output = crate::server::jsonrpc::MethodResponse> + Send + 'a {
        use crate::server::jsonrpc::{ErrorCode, ErrorObject, MethodResponse};

        let params: serde_json::Value = request
            .params
            .as_deref()
            .map_or(serde_json::Value::Null, |raw| {
                serde_json::from_str(raw.get()).expect("params are JSON")
            });
        let method = request.method_name().to_owned();
        let response = match method.as_str() {
            "nosuchmethod" => MethodResponse::error(request.id, ErrorCode::MethodNotFound.into()),
            "getblock" if params[0] == "999999999" => MethodResponse::error(
                request.id,
                ErrorObject::new(-8, "Block height out of range"),
            ),
            method => MethodResponse::response(
                request.id,
                &Ok(serde_json::json!({ "method": method, "params": params })),
                usize::MAX,
            ),
        };
        std::future::ready(response)
    }

    fn notification<'a>(
        &self,
        _notification: crate::server::jsonrpc::Notification<'a>,
    ) -> impl Future<Output = crate::server::jsonrpc::MethodResponse> + Send + 'a {
        std::future::ready(crate::server::jsonrpc::MethodResponse::notification())
    }
}

/// Ycash: sends `body` through the compatibility middleware and the JSON-RPC server, with
/// `cookie` if set, returning the response as JSON.
#[cfg(feature = "ycash")]
async fn batch_answer(
    body: &str,
    cookie: Option<crate::server::cookie::Cookie>,
    authorization: Option<String>,
) -> Result<serde_json::Value, BoxError> {
    use http_body_util::BodyExt;

    let inner = crate::server::http::JsonRpcHttpService::new(
        EchoRpc,
        crate::server::MAX_RPC_BATCH_REQUESTS,
        usize::MAX,
    );
    let mut builder = HttpRequest::builder()
        .method("POST")
        .header("content-type", "application/json");
    if let Some(authorization) = authorization {
        builder = builder.header("authorization", authorization);
    }
    let request = builder
        .body(HttpBody::from(body.to_owned()))
        .expect("valid request");
    let mut middleware = HttpRequestMiddleware::new(inner, cookie, 2_097_152);
    let response = middleware.call(request).await?;
    assert_eq!(response.status(), 200, "{body}");
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes).expect("the response is JSON"))
}

/// Ycash: the HTTP status the middleware and the JSON-RPC server answer `body` with.
#[cfg(feature = "ycash")]
async fn batch_status(
    body: &str,
    cookie: Option<crate::server::cookie::Cookie>,
    authorization: Option<String>,
) -> hyper::StatusCode {
    let inner = crate::server::http::JsonRpcHttpService::new(
        EchoRpc,
        crate::server::MAX_RPC_BATCH_REQUESTS,
        usize::MAX,
    );
    let mut builder = HttpRequest::builder()
        .method("POST")
        .header("content-type", "application/json");
    if let Some(authorization) = authorization {
        builder = builder.header("authorization", authorization);
    }
    let request = builder
        .body(HttpBody::from(body.to_owned()))
        .expect("valid request");
    let mut middleware = HttpRequestMiddleware::new(inner, cookie, 2_097_152);
    middleware.call(request).await.expect("an answer").status()
}

/// Ycash: the answer ycashd gives to one entry of a batch (`JSONRPCReplyObj`,
/// `src/rpc/protocol.cpp`): exactly `result`, `error` and `id`, `result` null on an error.
#[cfg(feature = "ycash")]
fn ycashd_entry(
    id: serde_json::Value,
    result: serde_json::Value,
    error: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({ "result": result, "error": error, "id": id })
}

/// Ycash: the result [`EchoRpc`] gives.
#[cfg(feature = "ycash")]
fn echoed(method: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "method": method, "params": params })
}

/// Ycash (beta3 item 7): the batches Inzyght sends, byte for byte (`BlockchainState.cc`
/// `update_state_on_block_event`; `ycash_rpc_client.cc` `batch_get_block_headers`, whose ids are
/// heights): entries without `"jsonrpc"`, answered as ycashd answers them, in order.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_inzyght_batches_are_answered_as_ycashd_answers_them() {
    use serde_json::{json, Value};

    let state = r#"[{"id":1,"method":"getblockchaininfo","params":[]},{"id":2,"method":"getnetworkinfo","params":[]},{"id":3,"method":"getpeerinfo","params":[]},{"id":4,"method":"getmininginfo","params":[]},{"id":5,"method":"getrawmempool","params":[true]}]"#;
    let expected: Vec<Value> = [
        ("getblockchaininfo", json!([])),
        ("getnetworkinfo", json!([])),
        ("getpeerinfo", json!([])),
        ("getmininginfo", json!([])),
        ("getrawmempool", json!([true])),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, (method, params))| ycashd_entry(json!(i + 1), echoed(method, params), Value::Null))
    .collect();
    let answer = batch_answer(state, None, None).await.expect("an answer");
    assert_eq!(answer, Value::Array(expected), "{answer}");

    let blocks = r#"[{"id":510000,"method":"getblock","params":["510000",1]},{"id":510001,"method":"getblock","params":["510001",1]},{"id":510002,"method":"getblock","params":["510002",1]}]"#;
    let answer = batch_answer(blocks, None, None).await.expect("an answer");
    let expected: Vec<Value> = (510_000..510_003)
        .map(|h| {
            ycashd_entry(
                json!(h),
                echoed("getblock", json!([h.to_string(), 1])),
                Value::Null,
            )
        })
        .collect();
    assert_eq!(answer, Value::Array(expected), "{answer}");
}

/// Ycash (beta3 item 7): a batch with one failing entry. The failing entry gets ycashd's error
/// shape (`result` null, the error, its id) and the others their results, in order.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_one_point_zero_batch_with_a_failing_entry() {
    use serde_json::{json, Value};

    let body = r#"[{"id":510000,"method":"getblock","params":["510000",1]},{"id":999999999,"method":"getblock","params":["999999999",1]},{"id":7,"method":"nosuchmethod","params":[]}]"#;
    let answer = batch_answer(body, None, None).await.expect("an answer");
    let expected = json!([
        ycashd_entry(
            json!(510000),
            echoed("getblock", json!(["510000", 1])),
            Value::Null
        ),
        ycashd_entry(
            json!(999999999),
            Value::Null,
            json!({"code": -8, "message": "Block height out of range"})
        ),
        ycashd_entry(
            json!(7),
            Value::Null,
            json!({"code": -32601, "message": "Method not found"})
        ),
    ]);
    assert_eq!(answer, expected, "{answer}");
}

/// Ycash (beta3 item 7): a batch that mixes bitcoind-style, lightwalletd-style (`"1.0"`) and 2.0
/// entries, a 2.0 notification and an invalid entry. Each entry is answered in its own version,
/// as a single request of that version is: a 2.0 entry in 2.0, a lightwalletd entry with
/// `"jsonrpc":"1.0"`, a bitcoind entry with ycashd's keys. The notification gets no answer, as
/// JSON-RPC 2.0 says; an invalid entry keeps the server's 2.0 error.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_mixed_one_point_zero_and_two_point_zero_batch() {
    use serde_json::{json, Value};

    let body = r#"[{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1},{"method":"getblockcount","params":[],"id":2},{"jsonrpc":"1.0","method":"getblockcount","params":[],"id":"lwd"},{"jsonrpc":"2.0","method":"getblockcount"},{"jsonrpc":"1.0","method":"getinfo","id":4},{"method":"nosuchmethod","params":[],"id":5},{"jsonrpc":"2.0","method":"nosuchmethod","params":[],"id":6},7]"#;
    let answer = batch_answer(body, None, None).await.expect("an answer");
    let not_found = json!({"code": -32601, "message": "Method not found"});
    let expected = json!([
        {"jsonrpc": "2.0", "id": 1, "result": echoed("getblockcount", json!([]))},
        ycashd_entry(json!(2), echoed("getblockcount", json!([])), Value::Null),
        {"jsonrpc": "1.0", "id": "lwd", "result": echoed("getblockcount", json!([])), "error": null},
        {"jsonrpc": "1.0", "id": 4, "result": echoed("getinfo", Value::Null), "error": null},
        ycashd_entry(json!(5), Value::Null, not_found.clone()),
        {"jsonrpc": "2.0", "id": 6, "error": not_found},
        {"jsonrpc": "2.0", "id": null, "error": {"code": -32600, "message": "Invalid request"}},
    ]);
    assert_eq!(answer, expected, "{answer}");
}

/// Ycash (beta3 item 7): ycashd answers an empty batch with `[]` (`JSONRPCExecBatch` of no
/// entries). A batch of only 2.0 entries is answered exactly as before.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_empty_batch_and_two_point_zero_batch() {
    use serde_json::json;

    for empty in ["[]", " [ ] "] {
        let answer = batch_answer(empty, None, None).await.expect("an answer");
        assert_eq!(answer, json!([]), "{empty}: {answer}");
    }

    let body = r#"[{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1},{"jsonrpc":"2.0","method":"nosuchmethod","params":[],"id":2}]"#;
    let answer = batch_answer(body, None, None).await.expect("an answer");
    assert_eq!(
        answer,
        json!([
            {"jsonrpc": "2.0", "id": 1, "result": echoed("getblockcount", json!([]))},
            {"jsonrpc": "2.0", "id": 2, "error": {"code": -32601, "message": "Method not found"}},
        ]),
        "{answer}"
    );
}

/// Ycash (beta3 item 7): the limits hold for 1.0 batches. A batch above the server's entry limit
/// is refused whole, before any entry runs; an unauthenticated batch is refused; a body above the
/// size limit is refused.
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_one_point_zero_batch_limits_hold() {
    use serde_json::json;

    let entry = r#"{"id":1,"method":"getblockcount","params":[]}"#;
    let largest = format!(
        "[{}]",
        vec![entry; crate::server::MAX_RPC_BATCH_REQUESTS].join(",")
    );
    let answer = batch_answer(&largest, None, None).await.expect("an answer");
    assert_eq!(
        answer.as_array().map(Vec::len),
        Some(crate::server::MAX_RPC_BATCH_REQUESTS)
    );
    assert_eq!(
        answer[0],
        ycashd_entry(
            json!(1),
            echoed("getblockcount", json!([])),
            serde_json::Value::Null
        )
    );

    let too_large = format!(
        "[{}]",
        vec![entry; crate::server::MAX_RPC_BATCH_REQUESTS + 1].join(",")
    );
    let answer = batch_answer(&too_large, None, None)
        .await
        .expect("an answer");
    assert_eq!(answer["error"]["code"], -32010, "{answer}");
    assert_eq!(answer["id"], serde_json::Value::Null, "{answer}");

    let cookie = crate::server::cookie::Cookie::default();
    let batch = format!("[{entry}]");
    assert_eq!(
        batch_status(&batch, Some(cookie.clone()), None).await,
        hyper::StatusCode::UNAUTHORIZED,
        "a batch without credentials is refused"
    );
    assert_eq!(
        batch_status(
            &batch,
            Some(cookie),
            Some(format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    "__cookie__:wrong"
                )
            ))
        )
        .await,
        hyper::StatusCode::UNAUTHORIZED,
        "a batch with a wrong cookie is refused"
    );

    let request = HttpRequest::builder()
        .method("POST")
        .header("content-type", "application/json")
        .body(HttpBody::from(format!("[{entry},{entry}]")))
        .expect("valid request");
    let mut middleware = HttpRequestMiddleware::new(MockRpcService, None, entry.len());
    assert!(
        middleware.call(request).await.is_err(),
        "a batch above the body size limit is refused"
    );
}

/// Ycash (beta3 item 7, review L1 and L2): a 1.0 member whose id the server does not take
/// (negative, fractional, above `u64`, a boolean, an object) is not turned into a 2.0
/// notification, which would get no answer: it is forwarded unchanged and answered with the
/// server's invalid request error, and no method runs. A 1.0 member with `"id": null` or no id
/// gets the same error, as a single request of that kind does (ycashd answers both with
/// `"id": null`; recorded in the parity table).
#[cfg(feature = "ycash")]
#[tokio::test]
async fn ycash_one_point_zero_batch_members_with_ids_the_server_does_not_take() {
    use serde_json::{json, Value};

    let members = [
        r#"{"id":-1,"method":"getblockcount","params":[]}"#,
        r#"{"id":1.5,"method":"getblockcount","params":[]}"#,
        r#"{"id":18446744073709551616,"method":"getblockcount","params":[]}"#,
        r#"{"id":true,"method":"sendrawtransaction","params":["00"]}"#,
        r#"{"jsonrpc":"1.0","id":{},"method":"getblockcount","params":[]}"#,
        r#"{"id":null,"method":"getblockcount","params":[]}"#,
        r#"{"jsonrpc":"1.0","method":"getblockcount","params":[]}"#,
        r#"{"id":8,"method":"getblockcount","params":[]}"#,
    ];
    let body = format!("[{}]", members.join(","));
    let answer = batch_answer(&body, None, None).await.expect("an answer");
    let invalid = json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": {"code": -32600, "message": "Invalid request"},
    });
    let mut expected = vec![invalid; members.len() - 1];
    expected.push(ycashd_entry(
        json!(8),
        echoed("getblockcount", json!([])),
        Value::Null,
    ));
    assert_eq!(answer, Value::Array(expected), "{answer}");
}

/// A request with a wrong or missing cookie is answered `401 Unauthorized` with a Basic challenge,
/// as zcashd and ycashd answer, and never reaches the RPC service. Before, the middleware failed
/// the request and the server closed the connection without a response, so a client holding the
/// cookie of a previous start could not tell that it should re-read it.
#[tokio::test]
async fn wrong_cookie_is_answered_401() {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    use crate::server::cookie::{self, Cookie};

    let dir = tempfile::tempdir().expect("temp dir");
    let current = Cookie::default();
    cookie::write_to_disk(&current, dir.path(), None).expect("cookie written");
    let line = std::fs::read_to_string(dir.path().join(".cookie")).expect("cookie read");
    let previous = Cookie::default();
    cookie::write_to_disk(&previous, dir.path(), Some("old")).expect("cookie written");
    let stale = std::fs::read_to_string(dir.path().join("old")).expect("cookie read");

    for auth in [
        Some(stale.trim().to_string()),
        Some("__cookie__:".to_string()),
        None,
    ] {
        let mut builder = HttpRequest::builder()
            .method("POST")
            .header("content-type", "application/json");
        if let Some(auth) = auth {
            builder = builder.header("authorization", format!("Basic {}", STANDARD.encode(auth)));
        }
        let request = builder
            .body(HttpBody::from(
                r#"{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}"#.to_string(),
            ))
            .expect("valid request");
        let mut middleware =
            HttpRequestMiddleware::new(PanicRpcService, Some(current.clone()), 2_097_152);
        let response = middleware
            .call(request)
            .await
            .expect("answered, not failed");
        assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(hyper::header::WWW_AUTHENTICATE),
            Some(&hyper::header::HeaderValue::from_static(
                "Basic realm=\"jsonrpc\""
            ))
        );
    }

    // the current cookie still reaches the service
    let request = HttpRequest::builder()
        .method("POST")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Basic {}", STANDARD.encode(line.trim())),
        )
        .body(HttpBody::from(
            r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#.to_string(),
        ))
        .expect("valid request");
    let mut middleware = HttpRequestMiddleware::new(MockRpcService, Some(current), 2_097_152);
    let response = middleware.call(request).await.expect("answered");
    assert_eq!(response.status(), hyper::StatusCode::OK);
}

/// An inner service a refused request must never reach.
#[derive(Clone)]
struct PanicRpcService;

impl Service<HttpRequest> for PanicRpcService {
    type Response = HttpResponse;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: HttpRequest) -> Self::Future {
        panic!("an unauthenticated request reached the RPC service")
    }
}
