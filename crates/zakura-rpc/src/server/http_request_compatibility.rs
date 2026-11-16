//! Compatibility fixes for JSON-RPC HTTP requests.
//!
//! These fixes are applied at the HTTP level, before the RPC request is parsed.

use std::future::Future;

use std::pin::Pin;

use futures::{future, FutureExt};
use http_body_util::{BodyExt, Limited};
use hyper::header;
use serde::{Deserialize, Serialize};
use tower::BoxError;
use tower::Service;

use super::{
    cookie::Cookie,
    http::{HttpBody, HttpRequest, HttpResponse},
    jsonrpc::ErrorObject,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// HTTP [`HttpRequestMiddleware`] with compatibility workarounds.
///
/// This middleware makes the following changes to HTTP requests:
///
/// ### Remove `jsonrpc` field in JSON RPC 1.0
///
/// Removes "jsonrpc: 1.0" fields from requests,
/// because the "jsonrpc" field was only added in JSON-RPC 2.0.
///
/// <http://www.simple-is-better.org/rpc/#differences-between-1-0-and-2-0>
///
/// Ycash: the same rewrite applies to each entry of a batch, and each entry's response is mapped
/// back to that entry's version, as ycashd answers a batch of 1.0 requests (`JSONRPCExecBatch`,
/// `src/rpc/server.cpp`). An empty batch gets ycashd's answer, `[]`.
///
/// ### Add missing `content-type` HTTP header
///
/// Some RPC clients don't include a `content-type` HTTP header.
/// But unlike web browsers, the RPC server does not do content sniffing.
///
/// If there is no `content-type` header, we assume the content is JSON,
/// and let the parser error if we are incorrect.
///
/// ### Authenticate incoming requests
///
/// If the cookie-based RPC authentication is enabled, check that the incoming request contains the
/// authentication cookie.
///
/// This enables compatibility with `zcash-cli`.
///
/// ## Security
///
/// Any user-specified data in RPC requests is hex or base58check encoded.
/// We assume lightwalletd validates data encodings before sending it on to Zebra.
/// So any fixes Zebra performs won't change user-specified data.
#[derive(Clone, Debug)]
pub struct HttpRequestMiddleware<S> {
    service: S,
    cookie: Option<Cookie>,
    max_request_body_size: usize,
}

impl<S> HttpRequestMiddleware<S> {
    /// Create a new `HttpRequestMiddleware` with the given service, cookie, and request body size limit.
    pub fn new(service: S, cookie: Option<Cookie>, max_request_body_size: usize) -> Self {
        Self {
            service,
            cookie,
            max_request_body_size,
        }
    }

    /// Check if the request is authenticated.
    pub fn check_credentials(&self, headers: &header::HeaderMap) -> bool {
        self.cookie.as_ref().is_none_or(|internal_cookie| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|auth_header| auth_header.to_str().ok())
                .and_then(|auth_header| auth_header.split_whitespace().nth(1))
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .and_then(|request_cookie| request_cookie.split(':').nth(1).map(String::from))
                .is_some_and(|passwd| internal_cookie.authenticate(passwd))
        })
    }

    /// Insert or replace client supplied `content-type` HTTP header to `application/json` in the following cases:
    ///
    /// - no `content-type` supplied.
    /// - supplied `content-type` start with `text/plain`, for example:
    ///   - `text/plain`
    ///   - `text/plain;`
    ///   - `text/plain; charset=utf-8`
    ///
    /// `application/json` is the only `content-type` accepted by the Zebra rpc endpoint:
    ///
    /// <https://github.com/paritytech/jsonrpc/blob/38af3c9439aa75481805edf6c05c6622a5ab1e70/http/src/handler.rs#L582-L584>
    ///
    /// # Security
    ///
    /// - `content-type` headers exist so that applications know they are speaking the correct protocol with the correct format.
    ///   We can be a bit flexible, but there are some types (such as binary) we shouldn't allow.
    ///   In particular, the "application/x-www-form-urlencoded" header should be rejected, so browser forms can't be used to attack
    ///   a local RPC port. See "The Role of Routers in the CSRF Attack" in
    ///   <https://www.invicti.com/blog/web-security/importance-content-type-header-http-requests/>
    /// - Checking all the headers is secure, but only because hyper has custom code that just reads the first content-type header.
    ///   <https://github.com/hyperium/headers/blob/f01cc90cf8d601a716856bc9d29f47df92b779e4/src/common/content_type.rs#L102-L108>
    pub fn insert_or_replace_content_type_header(headers: &mut header::HeaderMap) {
        if !headers.contains_key(header::CONTENT_TYPE)
            || headers
                .get(header::CONTENT_TYPE)
                .filter(|value| {
                    value
                        .to_str()
                        .ok()
                        .unwrap_or_default()
                        .starts_with("text/plain")
                })
                .is_some()
        {
            headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("application/json"),
            );
        }
    }

    /// Maps whatever JSON-RPC version the client is using to JSON-RPC 2.0.
    async fn request_to_json_rpc_2<B>(
        request: HttpRequest<B>,
        max_request_body_size: usize,
    ) -> Result<(ClientVersions, HttpRequest<HttpBody>), BoxError>
    where
        B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = request.into_parts();
        let bytes = Limited::new(body, max_request_body_size)
            .collect()
            .await?
            .to_bytes();
        let (versions, bytes) =
            if let Ok(request) = serde_json::from_slice::<'_, JsonRpcRequest>(bytes.as_ref()) {
                let version = request.version();
                if matches!(version, JsonRpcVersion::Unknown) {
                    (ClientVersions::Single(version), bytes)
                } else {
                    (
                        ClientVersions::Single(version),
                        serde_json::to_vec(&request.into_2()).expect("valid").into(),
                    )
                }
            } else {
                batch_to_json_rpc_2(bytes)
            };
        Ok((
            versions,
            HttpRequest::from_parts(parts, HttpBody::from(bytes.as_ref().to_vec())),
        ))
    }
    /// Maps JSON-2.0 to whatever JSON-RPC version the client is using.
    async fn response_from_json_rpc_2(
        versions: ClientVersions,
        response: HttpResponse<HttpBody>,
    ) -> Result<HttpResponse<HttpBody>, BoxError> {
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let bytes = match versions {
            ClientVersions::Single(version) => {
                if let Ok(response) = serde_json::from_slice::<'_, JsonRpcResponse>(bytes.as_ref())
                {
                    serde_json::to_vec(&response.into_version(version))
                        .expect("valid")
                        .into()
                } else {
                    bytes
                }
            }
            #[cfg(feature = "ycash")]
            ClientVersions::Batch(versions) => batch_response_from_json_rpc_2(&versions, bytes),
            #[cfg(feature = "ycash")]
            ClientVersions::EmptyBatch => empty_batch_response(bytes),
        };
        Ok(HttpResponse::from_parts(
            parts,
            HttpBody::from(bytes.as_ref().to_vec()),
        ))
    }
}

/// Implement the Layer for HttpRequestMiddleware to allow injecting the cookie
#[derive(Clone)]
pub struct HttpRequestMiddlewareLayer {
    cookie: Option<Cookie>,
    max_request_body_size: usize,
}

impl HttpRequestMiddlewareLayer {
    /// Create a new `HttpRequestMiddlewareLayer` with the given cookie and request body size limit.
    pub fn new(cookie: Option<Cookie>, max_request_body_size: usize) -> Self {
        Self {
            cookie,
            max_request_body_size,
        }
    }
}

impl<S> tower::Layer<S> for HttpRequestMiddlewareLayer {
    type Service = HttpRequestMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        HttpRequestMiddleware::new(service, self.cookie.clone(), self.max_request_body_size)
    }
}

impl<S, B> Service<HttpRequest<B>> for HttpRequestMiddleware<S>
where
    S: Service<HttpRequest, Response = HttpResponse> + std::clone::Clone + Send + 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
    B: hyper::body::Body<Data = hyper::body::Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, mut request: HttpRequest<B>) -> Self::Future {
        // Check if the request is authenticated
        if !self.check_credentials(request.headers_mut()) {
            let error = ErrorObject::new(401, "unauthenticated method");
            // TODO: Error object is not being returned to the user but an empty response.
            return future::err(BoxError::from(error)).boxed();
        }

        // Fix the request headers.
        Self::insert_or_replace_content_type_header(request.headers_mut());

        let mut service = self.service.clone();
        let max_request_body_size = self.max_request_body_size;

        async move {
            let (versions, request) =
                Self::request_to_json_rpc_2(request, max_request_body_size).await?;
            let response = service.call(request).await.map_err(Into::into)?;
            Self::response_from_json_rpc_2(versions, response).await
        }
        .boxed()
    }
}

/// The JSON-RPC versions a request body used, recorded to map the responses back.
#[derive(Debug)]
enum ClientVersions {
    /// A single request, or a body this middleware forwards unchanged.
    Single(JsonRpcVersion),
    /// Ycash: a batch with at least one 1.0 entry. The version of each entry the server answers,
    /// in order: every entry except a 2.0 notification.
    #[cfg(feature = "ycash")]
    Batch(Vec<JsonRpcVersion>),
    /// Ycash: an empty batch.
    #[cfg(feature = "ycash")]
    EmptyBatch,
}

/// Without the `ycash` feature a batch is forwarded unchanged, as upstream does.
#[cfg(not(feature = "ycash"))]
fn batch_to_json_rpc_2(bytes: hyper::body::Bytes) -> (ClientVersions, hyper::body::Bytes) {
    (ClientVersions::Single(JsonRpcVersion::Unknown), bytes)
}

/// Ycash: maps each 1.0 entry of a batch to JSON-RPC 2.0, as a single request is mapped.
///
/// ycashd runs each entry of a batch as a request of its own and answers every one in order
/// (`JSONRPCExecBatch`, `src/rpc/server.cpp`), whether or not it says `"jsonrpc"`; the server
/// here takes only 2.0 entries. A body that is not a JSON array, a batch with more entries than
/// the server takes (which the server rejects before decoding any entry), and a batch of only
/// 2.0 or invalid entries are forwarded unchanged.
#[cfg(feature = "ycash")]
fn batch_to_json_rpc_2(bytes: hyper::body::Bytes) -> (ClientVersions, hyper::body::Bytes) {
    use std::borrow::Cow;

    use serde_json::value::RawValue;

    use super::jsonrpc::{Notification, Request};

    let unchanged = ClientVersions::Single(JsonRpcVersion::Unknown);
    let Ok(entries) = serde_json::from_slice::<Vec<&RawValue>>(bytes.as_ref()) else {
        return (unchanged, bytes);
    };
    if entries.is_empty() {
        return (ClientVersions::EmptyBatch, bytes);
    }
    if entries.len() > super::MAX_RPC_BATCH_REQUESTS {
        return (unchanged, bytes);
    }

    let mut versions = Vec::with_capacity(entries.len());
    let mut rewritten = Vec::with_capacity(entries.len());
    let mut any_one_point_zero = false;
    for entry in entries {
        let (version, entry) = match serde_json::from_str::<JsonRpcRequest>(entry.get()) {
            Ok(request)
                if matches!(
                    request.version(),
                    JsonRpcVersion::Bitcoind | JsonRpcVersion::Lightwalletd
                ) =>
            {
                any_one_point_zero = true;
                (
                    request.version(),
                    Cow::Owned(serde_json::to_string(&request.into_2()).expect("valid")),
                )
            }
            _ => (JsonRpcVersion::Unknown, Cow::Borrowed(entry.get())),
        };
        // The server answers every entry except a notification, and classifies them as
        // `Body::parse` does: a call, else a notification, else an invalid entry.
        let answered = serde_json::from_str::<Request<'_>>(&entry).is_ok()
            || serde_json::from_str::<Notification<'_>>(&entry).is_err();
        if answered {
            versions.push(version);
        }
        rewritten.push(entry);
    }

    if !any_one_point_zero {
        return (unchanged, bytes);
    }
    let body = format!("[{}]", rewritten.join(","));
    (ClientVersions::Batch(versions), body.into())
}

/// Ycash: maps each response of a batch back to the version of the entry it answers.
///
/// A response that is not an array with one element per answered entry (a batch the server
/// rejected as a whole, with a single error) is returned unchanged.
#[cfg(feature = "ycash")]
fn batch_response_from_json_rpc_2(
    versions: &[JsonRpcVersion],
    bytes: hyper::body::Bytes,
) -> hyper::body::Bytes {
    use std::borrow::Cow;

    use serde_json::value::RawValue;

    let Ok(responses) = serde_json::from_slice::<Vec<&RawValue>>(bytes.as_ref()) else {
        return bytes;
    };
    if responses.len() != versions.len() {
        return bytes;
    }

    let mapped: Vec<Cow<'_, str>> = responses
        .into_iter()
        .zip(versions)
        .map(|(response, version)| match version {
            JsonRpcVersion::Bitcoind | JsonRpcVersion::Lightwalletd => {
                match serde_json::from_str::<JsonRpcResponse>(response.get()) {
                    Ok(parsed) => Cow::Owned(
                        serde_json::to_string(&parsed.into_version(*version)).expect("valid"),
                    ),
                    Err(_) => Cow::Borrowed(response.get()),
                }
            }
            JsonRpcVersion::TwoPointZero | JsonRpcVersion::Unknown => Cow::Borrowed(response.get()),
        })
        .collect();

    format!("[{}]", mapped.join(",")).into()
}

/// Ycash: ycashd answers an empty batch with an empty batch, `[]`, where a JSON-RPC 2.0 server
/// answers with an invalid request error. Any other response is returned unchanged.
#[cfg(feature = "ycash")]
fn empty_batch_response(bytes: hyper::body::Bytes) -> hyper::body::Bytes {
    match serde_json::from_slice::<JsonRpcResponse>(bytes.as_ref()) {
        Ok(JsonRpcResponse {
            error: Some(_),
            id: serde_json::Value::Null,
            ..
        }) => hyper::body::Bytes::from_static(b"[]"),
        _ => bytes,
    }
}

#[derive(Clone, Copy, Debug)]
enum JsonRpcVersion {
    /// bitcoind used a mishmash of 1.0, 1.1, and 2.0 for its JSON-RPC.
    Bitcoind,
    /// lightwalletd uses the above mishmash, but also breaks spec to include a
    /// `"jsonrpc": "1.0"` key.
    Lightwalletd,
    /// The client is indicating strict 2.0 handling.
    TwoPointZero,
    /// On parse errors we don't modify anything, and let the JSON-RPC server handle it.
    Unknown,
}

/// A version-agnostic JSON-RPC request.
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonrpc: Option<String>,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    fn version(&self) -> JsonRpcVersion {
        match (self.jsonrpc.as_deref(), &self.params, &self.id) {
            (
                Some("2.0"),
                _,
                None
                | Some(
                    serde_json::Value::Null
                    | serde_json::Value::String(_)
                    | serde_json::Value::Number(_),
                ),
            ) => JsonRpcVersion::TwoPointZero,
            (Some("1.0"), Some(_), Some(_)) => JsonRpcVersion::Lightwalletd,
            (None, Some(_), Some(_)) => JsonRpcVersion::Bitcoind,
            // Ycash: ycashd takes a 1.0 request whose `params` is null or absent as `[]`
            // (`JSONRequest::parse`, `src/rpc/server.cpp`); yindex sends `"params": null`. Both
            // deserialize to `None` here and are forwarded without `params`, which the methods
            // read as no arguments.
            #[cfg(feature = "ycash")]
            (Some("1.0"), None, Some(_)) => JsonRpcVersion::Lightwalletd,
            #[cfg(feature = "ycash")]
            (None, None, Some(_)) => JsonRpcVersion::Bitcoind,
            _ => JsonRpcVersion::Unknown,
        }
    }

    fn into_2(mut self) -> Self {
        self.jsonrpc = Some("2.0".into());
        self
    }
}
/// A version-agnostic JSON-RPC response.
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    jsonrpc: Option<String>,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    fn into_version(mut self, version: JsonRpcVersion) -> Self {
        match version {
            JsonRpcVersion::Bitcoind => {
                self.jsonrpc = None;
                self.result = self
                    .result
                    .or_else(|| serde_json::value::to_raw_value(&()).ok());
                self.error = self.error.or(Some(serde_json::Value::Null));
            }
            JsonRpcVersion::Lightwalletd => {
                self.jsonrpc = Some("1.0".into());
                self.result = self
                    .result
                    .or_else(|| serde_json::value::to_raw_value(&()).ok());
                self.error = self.error.or(Some(serde_json::Value::Null));
            }
            JsonRpcVersion::TwoPointZero => {
                // The server should be returning valid JSON-RPC 2.0 responses. However,
                // a valid result of `null` can be parsed into `None` by this parser, so
                // we map the result explicitly to `Null` when there is no error.
                assert_eq!(self.jsonrpc.as_deref(), Some("2.0"));
                if self.error.is_none() {
                    self.result = self
                        .result
                        .or_else(|| serde_json::value::to_raw_value(&()).ok());
                } else {
                    assert!(self.result.is_none());
                }
            }
            JsonRpcVersion::Unknown => (),
        }
        self
    }
}
