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
