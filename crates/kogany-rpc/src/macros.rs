//! `kogany_rpc_trait!`: zakura-rpc's `rpc_trait!` for a trait defined outside zakura-rpc.
//!
//! Zakura's macro (`crates/zakura-rpc/src/server/jsonrpc.rs`, `rpc_trait!`) cannot be reused
//! here, for two reasons:
//!
//! - it is `pub(crate)` (a `macro_rules!` macro without `#[macro_export]`), and its arms name
//!   their helpers through `$crate::server::jsonrpc`;
//! - it implements `RpcMethods` as a blanket `impl<T: Trait> RpcMethods for T`. In another crate
//!   that is a foreign trait on an uncovered type parameter, which the orphan rule forbids
//!   (E0210); in zakura-rpc it would overlap `RpcServer`'s own blanket implementation.
//!
//! So this macro takes the same trait syntax, and implements `RpcMethods` for a local wrapper,
//! `dispatch = Name`, defined as `pub struct Name<T>(pub T)`. Its parameter decoding is a copy of
//! the `@decode` arm of `rpc_trait!` at kogany-legacy `2b062412c5` (`jsonrpc.rs:960-1053`), over
//! the same public helpers (`Params`, `NextParam`, `MissingParam`, `param_name_matches`), so
//! positional and named parameters, omitted trailing `Option`s and the invalid-params errors
//! (`-32602`, which the server's middleware turns into zcashd's `-1`) behave exactly as for
//! `RpcServer`'s methods. The crate's tests pin that behaviour.
//!
//! Each method also names its access class (`access = Unauthenticated | Admin | Test`, Zakura's
//! `RpcAccess`), and the macro emits `Name::<T>::METHOD_ACCESS` and `METHOD_DOCS` (name and doc
//! text, for the OpenRPC work of plan W7-d) next to `RpcMethods::METHOD_NAMES`.

/// Defines an RPC method trait, a dispatch wrapper for it, and how JSON-RPC calls are decoded
/// and dispatched to its methods. See the module documentation.
#[macro_export]
macro_rules! kogany_rpc_trait {
    (
        $(#[doc = $trait_doc:literal])*
        pub trait $trait:ident {
            $(
                $(#[doc = $doc:literal])*
                #[method(name = $name:literal, access = $access:ident)]
                async fn $method:ident(&self $(, $arg:ident: $ty:ty)* $(,)?) -> $ret:ty;
            )*
        }
        dispatch = $dispatch:ident;
    ) => {
        $(#[doc = $trait_doc])*
        #[$crate::__private::async_trait]
        pub trait $trait {
            $(
                $(#[doc = $doc])*
                async fn $method(&self $(, $arg: $ty)*) -> $ret;
            )*
        }

        #[doc = concat!("Dispatches JSON-RPC calls to a [`", stringify!($trait), "`].")]
        #[derive(Clone, Debug)]
        pub struct $dispatch<T>(pub T);

        impl<T> $dispatch<T> {
            /// The access class of every method, in declaration order.
            pub const METHOD_ACCESS: &'static [(
                &'static str,
                $crate::__private::ExtensionAccess,
            )] = &[$(($name, $crate::__private::ExtensionAccess::$access)),*];

            /// The name and documentation of every method, in declaration order.
            pub const METHOD_DOCS: &'static [(&'static str, &'static str)] =
                &[$(($name, concat!($($doc, "\n"),*))),*];
        }

        impl<T> $dispatch<T>
        where
            T: $trait + Clone + Send + Sync + 'static,
        {
            /// These methods as a server extension.
            pub fn into_extension(self) -> $crate::__private::RpcExtension {
                $crate::__private::RpcExtension::new(self, Self::METHOD_ACCESS)
            }
        }

        impl<T> $crate::__private::RpcMethods for $dispatch<T>
        where
            T: $trait + Clone + Send + Sync + 'static,
        {
            const METHOD_NAMES: &'static [&'static str] = &[$($name),*];

            fn call<'a>(
                &'a self,
                method: &str,
                params: $crate::__private::jsonrpc::Params<'a>,
                id: $crate::__private::jsonrpc::Id<'a>,
                max_response_size: usize,
            ) -> Option<
                std::pin::Pin<
                    Box<
                        dyn std::future::Future<
                                Output = $crate::__private::jsonrpc::MethodResponse,
                            > + Send
                            + 'a,
                    >,
                >,
            > {
                match method {
                    $(
                        $name => Some(Box::pin(async move {
                            let result = match $crate::kogany_rpc_trait!(
                                @decode params; $($arg: $ty),*
                            ) {
                                Ok(($($arg,)*)) => self.0.$method($($arg),*).await,
                                Err(error) => Err(error),
                            };

                            $crate::__private::jsonrpc::MethodResponse::response(
                                id,
                                &result,
                                max_response_size,
                            )
                        })),
                    )*
                    _ => None,
                }
            }
        }
    };

    (@decode $params:ident;) => {
        $crate::__private::jsonrpc::RpcResult::Ok(())
    };
    (@decode $params:ident; $($arg:ident: $ty:ty),+) => {
        if $params.is_object() {
            struct ParamsObject {
                $($arg: $ty,)+
            }

            impl<'de> $crate::__private::serde::Deserialize<'de> for ParamsObject {
                fn deserialize<D: $crate::__private::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    struct ParamsVisitor;

                    impl<'de> $crate::__private::serde::de::Visitor<'de> for ParamsVisitor {
                        type Value = ParamsObject;

                        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                            f.write_str("struct ParamsObject")
                        }

                        fn visit_map<A: $crate::__private::serde::de::MapAccess<'de>>(
                            self,
                            mut map: A,
                        ) -> ::core::result::Result<ParamsObject, A::Error> {
                            $(let mut $arg: Option<$ty> = None;)+

                            while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                                $(
                                    if $crate::__private::jsonrpc::param_name_matches(
                                        &key,
                                        stringify!($arg),
                                    ) {
                                        if $arg.is_some() {
                                            return Err(
                                                $crate::__private::serde::de::Error::duplicate_field(
                                                    stringify!($arg),
                                                ),
                                            );
                                        }
                                        $arg = Some(map.next_value()?);
                                        continue;
                                    }
                                )+
                                map.next_value::<$crate::__private::serde::de::IgnoredAny>()?;
                            }

                            Ok(ParamsObject {
                                $(
                                    $arg: match $arg {
                                        Some(value) => value,
                                        None => $crate::__private::serde::Deserialize::deserialize(
                                            $crate::__private::jsonrpc::MissingParam::new(
                                                stringify!($arg),
                                            ),
                                        )?,
                                    },
                                )+
                            })
                        }
                    }

                    deserializer.deserialize_map(ParamsVisitor)
                }
            }

            match $params.parse::<ParamsObject>() {
                Ok(parsed) => Ok(($(parsed.$arg,)+)),
                Err(error) => {
                    $crate::__private::jsonrpc::log_invalid_params_object();
                    Err(error)
                }
            }
        } else {
            #[allow(unused_imports)]
            use $crate::__private::jsonrpc::{NextOptionalParam as _, NextRequiredParam as _};

            let mut sequence = $params.sequence();
            (|| -> $crate::__private::jsonrpc::RpcResult<_> {
                $(
                    let $arg: $ty = (&$crate::__private::jsonrpc::NextParam::<$ty>::new())
                        .next_param(&mut sequence)
                        .inspect_err(|_| {
                            $crate::__private::jsonrpc::log_invalid_param(
                                stringify!($arg),
                                stringify!($ty),
                                stringify!($ty).starts_with("Option"),
                            )
                        })?;
                )+

                Ok(($($arg,)+))
            })()
        }
    };
}
