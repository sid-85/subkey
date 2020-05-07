use jsonrpc_http_server::jsonrpc_core::{Error, IoHandler, Params};
use jsonrpc_http_server::ServerBuilder;

use super::crypto::crypto::{CryptoTypeId, Ss58AddressFormat};
use super::keystore::KeyStore;
use super::types::*;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::RwLock;

pub static ADDR: &str = "127.0.0.1:9933";

pub fn run(address: Option<&str>) {
    let address = address.unwrap_or(ADDR);

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
        let curve_type = param
            .curve_type
            .map(|x| CryptoTypeId::try_from(x.as_ref()).unwrap());

        let addr_format = param
            .address_format
            .map(|x| Ss58AddressFormat::try_from(x.as_ref()).unwrap());

        let ret = &ks_add
            .read()
            .unwrap()
            .get_new_address(name, password, curve_type, addr_format)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_import = ks.clone();
    io.add_method("import_new_address", move |params: Params| {
        let param: ImportParams = params.parse()?;
        let name: Option<&str> = param.name.as_ref().map(String::as_str);
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let curve_type = param
            .curve_type
            .map(|x| CryptoTypeId::try_from(x.as_ref()).unwrap());

        let addr_format = param
            .address_format
            .map(|x| Ss58AddressFormat::try_from(x.as_ref()).unwrap());
        let ret = &ks_import
            .read()
            .unwrap()
            .import_new_address(name, password, curve_type, addr_format, &param.phrase)
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

    let ks_accounts = ks.clone();
    io.add_method("accounts", move |_params: Params| {
        let ret = &ks_accounts
            .read()
            .unwrap()
            .accounts()
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_get_account_address = ks.clone();
    io.add_method("get_account_address", move |params: Params| {
        let param: AccountAddressParams = params.parse()?;
        let ret = &ks_get_account_address
            .read()
            .unwrap()
            .get_account_address(&param.name)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_get_account = ks.clone();
    io.add_method("get_account", move |params: Params| {
        let param: AccountParams = params.parse()?;
        let ret = &ks_get_account
            .read()
            .unwrap()
            .get_account(&param.addr)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_remove_account = ks.clone();
    io.add_method("remove_account", move |params: Params| {
        let param: AccountRemoveParams = params.parse()?;
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_remove_account
            .read()
            .unwrap()
            .remove_account(&param.name, password)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_change_name = ks.clone();
    io.add_method("change_name", move |params: Params| {
        let param: AccountNameChangeParams = params.parse()?;
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let ret = &ks_change_name
            .read()
            .unwrap()
            .change_name(&param.name, &param.new_name, password)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    let ks_change_password = ks.clone();
    io.add_method("change_password", move |params: Params| {
        let param: AccountPasswordChangeParams = params.parse()?;
        let password: Option<&str> = param.password.as_ref().map(String::as_str);
        let new_password: Option<&str> = param.new_password.as_ref().map(String::as_str);
        let ret = &ks_change_password
            .read()
            .unwrap()
            .change_password(&param.name, password, new_password)
            .map_err(|e| Error::invalid_params_with_details("exec error", e))?;
        Ok(serde_json::json!(ret))
    });

    io
}
