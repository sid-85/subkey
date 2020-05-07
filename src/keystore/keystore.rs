use super::super::crypto::*;
use super::json::Crypto as JCrypto;
use super::json::Password;
use super::json::Random;
use super::json::Version;
use super::keyfile::KeyFile;
use bip39::{Language, Mnemonic, MnemonicType};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::str;

// trait IKeyStore {
//     // Safely copies current wallet file to destination filename
//     fn backup_wallet(destination: &str) Result<String>;
//     // Safely copies source filename to current wallet file
//     fn import_wallet(source: &str) Result<String>;

//     // Returns all the account name & the transparent / shielded address
//      fn accounts() Result<String>;
//     // Returns the transparent / shielded address by the account name
//      fn get_account_address(account: &str) Result<String>;
//     // Returns the account name by the addr
//      fn get_account(addr: &str) Result<String>;

//     // delete the account
//      fn del_account(account: &str, password: &str) Result<String>;
//     // change name
//      fn change_name(account: &str, newaccount: &str, password: &str) Result<String>;
//     // change password
//      fn change_password(account: &str, oldPassword: &str, newPassword: &str) Result<String>;

//     // // Returns a new transparent address for receiving payments
//     // fn t_get_new_address(account: &str, password: &str, seed: Option<[u8;32]>) Result<String>;
//     // // Returns a new shielded address for receiving payments
//     // fn z_get_new_zaddress(account: &str, password: &str, seed: Option<[u8;32]>) Result<String>;

//     // // Returns the transparent address for receiving payments by the hexKey
//     // fn t_import_key(account: &str, password: &str, hexHey: &str) Result<String>;
//     // // Returns the shielded address for receiving payments by the hexKey
//     // fn z_import_key(account: &str, password: &str, hexHey: &str) Result<String>;
//     // Returns the hexKey by the account name
//     fn export_key(account: &str, password: &str) Result<String>;

//     // Returns the shielded address for receiving payments by the hex of full viewing key
//     fn z_import_viewingkey(account: &str, hexKey: &str) Result<String>;
//     // Returns the transparent address for receiving payments by the hex of public key
//     fn t_import_viewingkey(account: &str) Result<String>;
//     // Returns the hex of full viewing key of shielded address or public key of transparent address by the account name
//     fn export_viewingkey(account: &str) Result<String>;

//     // sign message
//     fn sign(account: &str, password: &str, msg: &str) Result<String>;
//     // spend
//     fn sendmany(account: &str, password: &str) Result<String>;

//     // Returns the utxos of a taddr or zaddr belonging to the wallet.
//     fn utxos(account: &str) Result<String>;
//     // Returns the balance of a taddr or zaddr belonging to the wallet.
//     fn get_balance(account: &str) Result<i64>;

//     // Returns up to 'count' most recent transactions skipping the first 'from' transactions for account 'account'.
//     fn transactions(account: &str, start: i32, count: i32) Result<String>;
// }

#[derive(derive_more::Display, derive_more::From)]
pub enum Error {
    KeyStore(String),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct Account {
    secret_phrase: String,
    secret_seed: String,
    public_key: String,
    ss58_address: String,
    curve_type: String,
}

pub struct KeyStore {
    keys_dir_path: String,
}

impl KeyStore {
    pub fn new(keys_dir_path: Option<&str>) -> Self {
        let keys_dir_path = keys_dir_path.unwrap_or(".keys").to_string();
        if !Path::new(&keys_dir_path).exists() {
            fs::create_dir_all(&keys_dir_path)
                .expect(&format!("keystore create_dir_all {}", keys_dir_path));
        }

        KeyStore {
            keys_dir_path: keys_dir_path,
        }
    }

    fn filename(&self, name: &str) -> String {
        format!("{}/{}.json", self.keys_dir_path, name)
    }

    fn should_exist(&self, name: &str) -> Result<bool> {
        let file_name = self.filename(name);
        if !Path::new(&file_name).exists() {
            return Err(Error::KeyStore(format!(
                "account name {} alreay exist",
                name
            )));
        }
        Ok(true)
    }

    fn should_not_exist(&self, name: &str) -> Result<bool> {
        let file_name = self.filename(name);
        if Path::new(&file_name).exists() {
            return Err(Error::KeyStore(format!(
                "account name {} alreay exist",
                name
            )));
        }
        Ok(true)
    }

    fn save_to_file(&self, name: &str, key: &KeyFile) -> Result<()> {
        let file_name = self.filename(name);
        let mut file = File::create(file_name)
            .map_err(|e| Error::KeyStore(format!("keyfile {} create : {:?}", name, e)))?;
        key.write(&mut file)
            .map_err(|e| Error::KeyStore(format!("keyfile {} write : {:?}", name, e)))?;
        Ok(())
    }

    fn load_from_file(&self, name: &str) -> Result<KeyFile> {
        let file_name = self.filename(name);
        let file = File::open(file_name)
            .map_err(|e| Error::KeyStore(format!("keyfile {} open : {:?}", name, e)))?;
        let key = KeyFile::load(&file)
            .map_err(|e| Error::KeyStore(format!("keyfile {} load : {:?}", name, e)))?;
        Ok(key)
    }

    fn phrase_to_key<T: Crypto>(
        phrase: &str,
        password: Option<&str>,
        curve_type: CryptoTypeId,
        address_format: Option<Ss58AddressFormat>,
    ) -> Result<KeyFile> {
        let (pair, _seed) = <T as Crypto>::Pair::from_phrase(phrase, None)
            .map_err(|e| Error::KeyStore(format!("Invalid phrase : {:?}", e)))?;

        let address_formt = address_format.unwrap_or_default();

        let address = pair.public().to_ss58check_with_version(address_formt);

        let id: [u8; 16] = Random::random();

        let v = Version::V3;

        let password = Password::from(password.unwrap_or(""));
        let crypto = JCrypto::encrypt(phrase.as_bytes(), &password)
            .map_err(|e| Error::KeyStore(format!("Invalid encrypt : {:?}", e)))?;

        let efvk = None;
        // if let Ss58AddressFormat::Shielded == address_format {
        // // TODO
        // }

        let key = KeyFile {
            id: From::from(id),
            version: v,
            address: address.clone(),
            curve: str::from_utf8(&curve_type.0[..]).unwrap().to_string(),
            crypto: crypto,
            efvk: efvk,
            meta: None,
        };
        Ok(key)
    }

    pub fn get_new_address(
        &self,
        name: Option<&str>,
        password: Option<&str>,
        curve_type: Option<CryptoTypeId>,
        address_format: Option<Ss58AddressFormat>,
    ) -> Result<String> {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase();
        // key
        let curve_type = curve_type.unwrap_or(ed25519::CRYPTO_ID);
        let key = match curve_type {
            ed25519::CRYPTO_ID => {
                Self::phrase_to_key::<Ed25519>(&phrase, password, curve_type, address_format)?
            }
            sr25519::CRYPTO_ID => {
                Self::phrase_to_key::<Sr25519>(&phrase, password, curve_type, address_format)?
            }
            ecdsa::CRYPTO_ID => {
                Self::phrase_to_key::<Ecdsa>(&phrase, password, curve_type, address_format)?
            }
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        };

        // key save
        let name = name.unwrap_or(&key.address);
        self.should_not_exist(name)?;
        self.save_to_file(name, &key)?;
        Ok(name.to_string())
    }

    pub fn import_new_address(
        &self,
        name: Option<&str>,
        password: Option<&str>,
        curve_type: Option<CryptoTypeId>,
        address_format: Option<Ss58AddressFormat>,
        phrase: &str,
    ) -> Result<String> {
        // key
        let curve_type = curve_type.unwrap_or(ed25519::CRYPTO_ID);
        let key = match curve_type {
            ed25519::CRYPTO_ID => {
                Self::phrase_to_key::<Ed25519>(&phrase, password, curve_type, address_format)?
            }
            sr25519::CRYPTO_ID => {
                Self::phrase_to_key::<Sr25519>(&phrase, password, curve_type, address_format)?
            }
            ecdsa::CRYPTO_ID => {
                Self::phrase_to_key::<Ecdsa>(&phrase, password, curve_type, address_format)?
            }
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        };

        // key save
        let name = name.unwrap_or(&key.address);
        self.should_not_exist(name)?;
        self.save_to_file(name, &key)?;
        Ok(name.to_string())
    }

    fn key_export<T: Crypto>(key: &KeyFile, password: Option<&str>) -> Result<Account> {
        let password = Password::from(password.unwrap_or("").to_string());
        let secret = key
            .crypto
            .decrypt(&password)
            .map_err(|e| Error::KeyStore(format!("Invalid password : {}", e)))?;

        let phrase = String::from_utf8(secret)
            .map_err(|e| Error::KeyStore(format!("Convert phrase : {}", e)))?;

        let (_pair, seed) = <T as Crypto>::Pair::from_phrase(&phrase, None)
            .map_err(|e| Error::KeyStore(format!("Invalid phrase : {:?}", e)))?;

        let (pubkey, _format) =
            <<T as Crypto>::Pair as Pair>::Public::from_ss58check_with_version(&key.address)
                .map_err(|e| Error::KeyStore(format!("Convert pubkey : {:?}", e)))?;

        assert_eq!(
            _pair.public().to_ss58check_with_version(_format),
            key.address.clone()
        );

        Ok(Account {
            secret_phrase: phrase.clone(),
            secret_seed: format_seed::<T>(seed),
            public_key: format_public_key::<T>(pubkey),
            ss58_address: key.address.clone(),
            curve_type: key.curve.clone(),
        })
    }

    pub fn export_address(&self, name: &str, password: Option<&str>) -> Result<Account> {
        self.should_exist(name)?;
        let key = self.load_from_file(name)?;
        let curve_type = CryptoTypeId::try_from(key.curve.as_ref()).unwrap();
        match curve_type {
            ed25519::CRYPTO_ID => Self::key_export::<Ed25519>(&key, password),
            sr25519::CRYPTO_ID => Self::key_export::<Sr25519>(&key, password),
            ecdsa::CRYPTO_ID => Self::key_export::<Ecdsa>(&key, password),
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        }
    }

    fn key_sign<T: Crypto>(key: &KeyFile, password: Option<&str>, msg: &str) -> Result<String> {
        let password = Password::from(password.unwrap_or("").to_string());
        let secret = key
            .crypto
            .decrypt(&password)
            .map_err(|e| Error::KeyStore(format!("Invalid password : {}", e)))?;

        let phrase = String::from_utf8(secret)
            .map_err(|e| Error::KeyStore(format!("Convert phrase : {}", e)))?;

        let (pair, _seed) = <T as Crypto>::Pair::from_phrase(&phrase, None)
            .map_err(|e| Error::KeyStore(format!("Invalid phrase : {:?}", e)))?;

        let signature = pair.sign(msg.as_bytes());
        Ok(serde_json::to_value(&signature)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string())
    }

    pub fn sign_message(&self, name: &str, password: Option<&str>, msg: &str) -> Result<String> {
        self.should_exist(name)?;
        let key = self.load_from_file(name)?;
        let curve_type = CryptoTypeId::try_from(key.curve.as_ref()).unwrap();
        match curve_type {
            ed25519::CRYPTO_ID => Self::key_sign::<Ed25519>(&key, password, msg),
            sr25519::CRYPTO_ID => Self::key_sign::<Sr25519>(&key, password, msg),
            ecdsa::CRYPTO_ID => Self::key_sign::<Ecdsa>(&key, password, msg),
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        }
    }

    fn key_verify<T: Crypto>(key: &KeyFile, msg: &str, signature: &str) -> Result<bool> {
        let (pubkey, _format) =
            <<T as Crypto>::Pair as Pair>::Public::from_ss58check_with_version(&key.address)
                .map_err(|e| Error::KeyStore(format!("Convert pubkey : {:?}", e)))?;

        let signature = serde_json::to_string(signature).unwrap();
        let signature: <<T as Crypto>::Pair as Pair>::Signature = serde_json::from_str(&signature)
            .map_err(|e| Error::KeyStore(format!("Invalid signature : {:?}", e)))?;

        let ret = <<T as Crypto>::Pair as Pair>::verify(&signature, msg, &pubkey);
        Ok(ret)
    }

    pub fn verify_message(&self, name: &str, msg: &str, signature: &str) -> Result<bool> {
        self.should_exist(name)?;
        let key = self.load_from_file(name)?;
        let curve_type = CryptoTypeId::try_from(key.curve.as_ref()).unwrap();
        match curve_type {
            ed25519::CRYPTO_ID => Self::key_verify::<Ed25519>(&key, msg, signature),
            sr25519::CRYPTO_ID => Self::key_verify::<Sr25519>(&key, msg, signature),
            ecdsa::CRYPTO_ID => Self::key_verify::<Ecdsa>(&key, msg, signature),
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        }
    }

    //==========================================================================================//
    // account
    //==========================================================================================//
    // Returns all the account name & the transparent / shielded address
    pub fn accounts(&self) -> Result<Vec<String>> {
        let mut names = vec![];
        let entrys = fs::read_dir(&self.keys_dir_path)
            .map_err(|e| Error::KeyStore(format!("keystore accouts read_dir {:?}", e)))?;
        for entry in entrys {
            let file = entry.unwrap().path();
            let filename = file.to_str().unwrap();
            let path = Path::new(&filename);
            if path.extension().unwrap().to_str().unwrap() == "json" {
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                let ret = self.load_from_file(&name);
                if let Ok(_) = ret {
                    names.push(name);
                } else {
                    println!("{:?}", ret);
                }
            }
        }
        Ok(names)
    }
    // Returns the transparent / shielded address by the account name
    pub fn get_account_address(&self, name: &str) -> Result<String> {
        self.should_exist(name)?;
        Ok(self.load_from_file(name)?.address)
    }
    // Returns the account name by the addr
    pub fn get_account(&self, addr: &str) -> Result<String> {
        let entrys = fs::read_dir(&self.keys_dir_path)
            .map_err(|e| Error::KeyStore(format!("keystore accouts read_dir {:?}", e)))?;
        for entry in entrys {
            let file = entry.unwrap().path();
            let filename = file.to_str().unwrap();
            let path = Path::new(&filename);
            if path.extension().unwrap() == "json" {
                let name = path.file_stem().unwrap().to_str().unwrap().to_string();
                let key = self.load_from_file(&name)?;
                if key.address == addr {
                    return Ok(name);
                }
            }
        }
        Err(Error::KeyStore(format!("not found")))
    }

    pub fn remove_account(&self, name: &str, password: Option<&str>) -> Result<bool> {
        self.export_address(name, password)?;
        fs::remove_file(self.filename(name))
            .map_err(|e| Error::KeyStore(format!("failed to remove account{:?}", e)))?;
        Ok(true)
    }
    pub fn change_name(&self, name: &str, new_name: &str, password: Option<&str>) -> Result<bool> {
        self.export_address(name, password)?;
        fs::rename(self.filename(name), self.filename(new_name))
            .map_err(|e| Error::KeyStore(format!("failed to change_name {:?}", e)))?;
        Ok(true)
    }

    pub fn key_change_password<T: Crypto>(
        key: &KeyFile,
        password: Option<&str>,
        new_password: Option<&str>,
    ) -> Result<KeyFile> {
        let password = Password::from(password.unwrap_or("").to_string());
        let new_password = Password::from(new_password.unwrap_or("").to_string());
        let secret = key
            .crypto
            .decrypt(&password)
            .map_err(|e| Error::KeyStore(format!("Invalid password : {}", e)))?;

        let crypto = JCrypto::encrypt(secret.as_slice(), &new_password)
            .map_err(|e| Error::KeyStore(format!("Invalid encrypt : {:?}", e)))?;

        let evfk = if let Some(crypto) = &key.efvk {
            let password_efvk = Password::from("");
            let secret_efvk = crypto
                .decrypt(&password_efvk)
                .map_err(|e| Error::KeyStore(format!("Invalid password : {}", e)))?;

            let crypto_efvk = JCrypto::encrypt(secret_efvk.as_slice(), &password_efvk)
                .map_err(|e| Error::KeyStore(format!("Invalid encrypt : {:?}", e)))?;
            Some(crypto_efvk)
        } else {
            None
        };

        Ok(KeyFile {
            id: key.id.clone(),
            version: key.version.clone(),
            address: key.address.clone(),
            curve: key.curve.clone(),
            crypto: crypto,
            efvk: evfk,
            meta: key.meta.clone(),
        })
    }

    pub fn change_password(
        &self,
        name: &str,
        password: Option<&str>,
        new_password: Option<&str>,
    ) -> Result<bool> {
        self.should_exist(name)?;
        let key = self.load_from_file(name)?;
        let curve_type = CryptoTypeId::try_from(key.curve.as_ref()).unwrap();
        let key = match curve_type {
            ed25519::CRYPTO_ID => {
                Self::key_change_password::<Ed25519>(&key, password, new_password)?
            }
            sr25519::CRYPTO_ID => {
                Self::key_change_password::<Sr25519>(&key, password, new_password)?
            }
            ecdsa::CRYPTO_ID => Self::key_change_password::<Ecdsa>(&key, password, new_password)?,
            _ => {
                return Err(Error::KeyStore(format!(
                    "Invalid curve type : {:?}",
                    curve_type
                )))
            }
        };
        self.save_to_file(name, &key)?;
        Ok(true)
    }
}
