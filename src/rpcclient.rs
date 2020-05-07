//! Helper to run commands against current node RPC

use super::types::*;
use hyper::rt;
use jsonrpc_core::futures::Future;
use jsonrpc_core_client::transports::http;
use jsonrpc_core_client::RpcChannel;
use jsonrpc_core_client::RpcError;
use jsonrpc_core_client::TypedClient;
use std::time::Duration;

struct JSONRPCClient(TypedClient);

impl From<RpcChannel> for JSONRPCClient {
    fn from(channel: RpcChannel) -> Self {
        JSONRPCClient(channel.into())
    }
}

pub struct RpcClient {
    url: String,
}

impl RpcClient {
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

macro_rules! impl_rpclient {
    ($($func_name:ident, $param_ty: ty),*) => {
        impl JSONRPCClient {
            $(fn $func_name(
                &self,
                params: $param_ty,
            ) -> impl Future<Item = String, Error = RpcError> {
                self.0.call_method(stringify!($func_name), "String", params)
            })*
        }

        impl RpcClient {
            $(pub fn $func_name(&self, params: $param_ty) -> Result<String, RpcError> {
                let url = self.url.clone();

                let (tx, rx) = std::sync::mpsc::channel();
                rt::run(
                    http::connect(&url)
                        .and_then(|client: JSONRPCClient| {
                            client.$func_name(params).map(move |result| {
                                drop(client);
                                let _ = tx.send(result);
                            })
                        })
                        .map_err(|e| println!("{} {:?}", stringify!($func_name), e)),
                );
                let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(result)
            })*
        }
    };
}

impl_rpclient!(add_new_address, AddParams);
impl_rpclient!(import_new_address, ImportParams);
impl_rpclient!(export_address, ExportParams);
impl_rpclient!(sign_message, SignMessageParams);
impl_rpclient!(verify_message, VerfiyMessageParams);
