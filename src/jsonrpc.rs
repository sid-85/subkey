use jsonrpc_http_server::jsonrpc_core::{Error, IoHandler, Params};
use jsonrpc_http_server::ServerBuilder;

use super::keystore::KeyStore;
use std::sync::Arc;
use std::sync::RwLock;

pub fn run(address: Option<&str>) {
    let address = address.unwrap_or("127.0.0.1:3030");

    let server = ServerBuilder::new(rpc_handler())
        .threads(3)
        .start_http(&address.parse().unwrap())
        .unwrap();

    server.wait();
}

pub fn rpc_handler() -> IoHandler {
    let ks = Arc::new(RwLock::new(KeyStore::new(None)));

    let mut io = IoHandler::new();

    let ks_add = ks.clone();
    io.add_method("add_new_address", move |params: Params| {
        let param: AddParams = params.parse()?;
        let name: Option<&str> = param.name.as_ref().map(String::as_str);
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_add
            .read()
            .unwrap()
            .get_new_address(name, password, None, None)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_import = ks.clone();
    io.add_method("import_new_address", move |params: Params| {
        let param: ImportParams = params.parse()?;
        let name: Option<&str> = param.name.as_ref().map(String::as_str);
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_import
            .read()
            .unwrap()
            .import_new_address(name, password, None, None, &param.phrase)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_export = ks.clone();
    io.add_method("export_address", move |params: Params| {
        let param: ExportParams = params.parse()?;
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_export
            .read()
            .unwrap()
            .export_address(&param.name, password)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_sign_message = ks.clone();
    io.add_method("sign_message", move |params: Params| {
        let param: SignMessageParams = params.parse()?;
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_sign_message
            .read()
            .unwrap()
            .sign_message(&param.name, password, &param.message)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_verify_message = ks.clone();
    io.add_method("verify_message", move |params: Params| {
        let param: VerfiyMessageParams = params.parse()?;
        let ret = &ks_verify_message
            .read()
            .unwrap()
            .verify_message(&param.name, &param.message, &param.signature)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    io
}

use serde::Deserialize;

#[derive(Deserialize)]
pub struct AddParams {
    name: Option<String>,
    password: Option<String>,
    curve_type: Option<String>,
    address_format: Option<String>,
}

#[derive(Deserialize)]
pub struct ImportParams {
    phrase: String,
    name: Option<String>,
    password: Option<String>,
    curve_type: Option<String>,
    address_format: Option<String>,
}

#[derive(Deserialize)]
pub struct ExportParams {
    name: String,
    password: Option<String>,
}

#[derive(Deserialize)]
pub struct SignMessageParams {
    name: String,
    password: Option<String>,
    message: String,
}

#[derive(Deserialize)]
pub struct VerfiyMessageParams {
    name: String,
    message: String,
    signature: String,
}
