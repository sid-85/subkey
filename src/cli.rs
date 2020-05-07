use super::crypto::{crypto::*, ecdsa, ed25519, sr25519};
use super::{jsonrpc::ADDR, rpcclient, types::*};
use clap::ArgMatches;

pub fn run_keys(args: &ArgMatches) {
    match args.subcommand() {
        ("gen", Some(args)) => {
            add_new_address(args);
        }
        ("import", Some(args)) => {
            import_new_address(args);
        }
        ("export", Some(args)) => {
            export_address(args);
        }
        ("sign", Some(args)) => {
            sign_message(args);
        }
        ("verify", Some(args)) => {
            verify_message(args);
        }
        ("accounts", Some(args)) => {
            accounts(args);
        }
        ("account", Some(args)) => {
            account(args);
        }
        ("address", Some(args)) => {
            address(args);
        }
        ("remove", Some(args)) => {
            remove(args);
        }
        ("rename", Some(args)) => {
            rename(args);
        }
        ("password", Some(args)) => {
            password(args);
        }
        _ => println!("{}", args.usage()),
    }
}

fn add_new_address(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let curve_type = if matches.is_present("sr25519") {
        Some(sr25519::CRYPTO_ID)
    } else if matches.is_present("secp256k1") {
        Some(ecdsa::CRYPTO_ID)
    } else {
        Some(ed25519::CRYPTO_ID)
    };

    let addr_format = if matches.is_present("shielded") {
        Some(Ss58AddressFormat::Shielded)
    } else {
        Some(Ss58AddressFormat::Transparent)
    };

    let name = matches.value_of("name");
    let password = matches.value_of("password");

    let params = AddParams {
        name: name.map(|x| x.to_string()),
        password: password.map(|x| x.to_string()),
        curve_type: curve_type.map(|x| String::from(x)),
        address_format: addr_format.map(|x| String::from(x)),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).add_new_address(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn import_new_address(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let curve_type = if matches.is_present("sr25519") {
        Some(sr25519::CRYPTO_ID)
    } else if matches.is_present("secp256k1") {
        Some(ecdsa::CRYPTO_ID)
    } else {
        Some(ed25519::CRYPTO_ID)
    };

    let addr_format = if matches.is_present("shielded") {
        Some(Ss58AddressFormat::Shielded)
    } else {
        Some(Ss58AddressFormat::Transparent)
    };
    let phrase = matches.value_of("phrase");
    let name = matches.value_of("name");
    let password = matches.value_of("password");

    let params = ImportParams {
        phrase: phrase.unwrap().to_string(),
        name: name.map(|x| x.to_string()),
        password: password.map(|x| x.to_string()),
        curve_type: curve_type.map(|x| String::from(x)),
        address_format: addr_format.map(|x| String::from(x)),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).import_new_address(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}
fn export_address(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let password = matches.value_of("password");

    let params = ExportParams {
        name: name.unwrap().to_string(),
        password: password.map(|x| x.to_string()),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).export_address(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}
fn sign_message(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let password = matches.value_of("password");
    let message = matches.value_of("message");

    let params = SignMessageParams {
        name: name.unwrap().to_string(),
        password: password.map(|x| x.to_string()),
        message: message.unwrap().to_string(),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).sign_message(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}
fn verify_message(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let signature = matches.value_of("signature");
    let message = matches.value_of("message");

    let params = VerfiyMessageParams {
        name: name.unwrap().to_string(),
        message: message.unwrap().to_string(),
        signature: signature.unwrap().to_string(),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).verify_message(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn accounts(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));

    let params = AccountsParams {};
    let ret = rpcclient::RpcClient::new(url.to_string()).accounts(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn account(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let addr = matches.value_of("addr");

    let params = AccountParams {
        addr: addr.unwrap().to_string(),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).get_account(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn address(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");

    let params = AccountAddressParams {
        name: name.unwrap().to_string(),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).get_account_address(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn remove(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let password = matches.value_of("password");

    let params = AccountRemoveParams {
        name: name.unwrap().to_string(),
        password: password.map(|x| x.to_string()),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).remove_account(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn rename(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let new_name = matches.value_of("new_name");
    let password = matches.value_of("password");

    let params = AccountNameChangeParams {
        name: name.unwrap().to_string(),
        new_name: new_name.unwrap().to_string(),
        password: password.map(|x| x.to_string()),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).change_name(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}

fn password(matches: &ArgMatches) {
    let url = format!("http://{}", matches.value_of("url").unwrap_or(ADDR));
    let name = matches.value_of("name");
    let password = matches.value_of("password");
    let new_password = matches.value_of("new_password");

    let params = AccountPasswordChangeParams {
        name: name.unwrap().to_string(),
        password: password.map(|x| x.to_string()),
        new_password: new_password.map(|x| x.to_string()),
    };
    let ret = rpcclient::RpcClient::new(url.to_string()).change_password(params);
    println!("{}", ret.unwrap_or_else(|e| format!("{:?}", e)));
}
