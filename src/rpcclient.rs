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

impl JSONRPCClient {
    fn add_new_address(&self, params: AddParams) -> impl Future<Item = String, Error = RpcError> {
        self.0.call_method("add_new_address", "String", params)
    }

    fn import_new_address(
        &self,
        params: ImportParams,
    ) -> impl Future<Item = String, Error = RpcError> {
        self.0.call_method("import_new_address", "String", params)
    }
    fn export_address(&self, params: ExportParams) -> impl Future<Item = String, Error = RpcError> {
        self.0.call_method("export_address", "String", params)
    }
    fn sign_message(
        &self,
        params: SignMessageParams,
    ) -> impl Future<Item = String, Error = RpcError> {
        self.0.call_method("sign_message", "String", params)
    }
    fn verify_message(
        &self,
        params: VerfiyMessageParams,
    ) -> impl Future<Item = String, Error = RpcError> {
        self.0.call_method("verify_message", "String", params)
    }
}

pub struct RpcClient {
    url: String,
}

impl RpcClient {
    pub fn new(url: String) -> Self {
        Self { url }
    }

    pub fn add_new_address(&self, params: AddParams) -> Result<String, RpcError> {
        let url = self.url.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        rt::run(
            http::connect(&url)
                .and_then(|client: JSONRPCClient| {
                    client.add_new_address(params).map(move |result| {
                        drop(client);
                        let _ = tx.send(result);
                    })
                })
                .map_err(|e| println!("add_new_address {:?}", e)),
        );
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    }

    pub fn export_address(&self, params: ExportParams) -> Result<String, RpcError> {
        let url = self.url.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        rt::run(
            http::connect(&url)
                .and_then(|client: JSONRPCClient| {
                    client.export_address(params).map(move |result| {
                        drop(client);
                        let _ = tx.send(result);
                    })
                })
                .map_err(|e| println!("export_address {:?}", e)),
        );
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    }

    pub fn sign_message(&self, params: SignMessageParams) -> Result<String, RpcError> {
        let url = self.url.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        rt::run(
            http::connect(&url)
                .and_then(|client: JSONRPCClient| {
                    client.sign_message(params).map(move |result| {
                        drop(client);
                        let _ = tx.send(result);
                    })
                })
                .map_err(|e| println!("sign_message {:?}", e)),
        );
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    }

    pub fn verify_message(&self, params: VerfiyMessageParams) -> Result<String, RpcError> {
        let url = self.url.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        rt::run(
            http::connect(&url)
                .and_then(|client: JSONRPCClient| {
                    client.verify_message(params).map(move |result| {
                        drop(client);
                        let _ = tx.send(result);
                    })
                })
                .map_err(|e| println!("verify_message {:?}", e)),
        );
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    }

    pub fn import_new_address(&self, params: ImportParams) -> Result<String, RpcError> {
        let url = self.url.clone();

        let (tx, rx) = std::sync::mpsc::channel();
        rt::run(
            http::connect(&url)
                .and_then(|client: JSONRPCClient| {
                    client.import_new_address(params).map(move |result| {
                        drop(client);
                        let _ = tx.send(result);
                    })
                })
                .map_err(|e| println!("import_new_address {:?}", e)),
        );
        let result = rx.recv_timeout(Duration::from_secs(10)).unwrap();
        Ok(result)
    }
}
