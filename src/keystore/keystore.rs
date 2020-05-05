use super::super::crypto::*;
use super::json::Crypto as JCrypto;
use super::json::Password;
use super::json::Random;
use super::json::Version;
use super::keyfile::KeyFile;
use bip39::{Language, Mnemonic, MnemonicType};
use serde::{Deserialize, Serialize};
use std::fs::File;
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
    name: String,
}

pub struct KeyStore {
    keys_dir_path: String,
}

impl KeyStore {
    pub fn new(keys_dir_path: Option<&str>) -> Self {
        KeyStore {
            keys_dir_path: keys_dir_path.unwrap_or(".keys").to_string(),
        }
    }
    // generate
    // import
    // sign
    // verfiy
    fn save_to_file(&self, name: &str, key: &KeyFile) -> Result<()> {
        let file_name = format!("{}/{}.json", self.keys_dir_path, name);
        let mut file = File::create(file_name)
            .map_err(|e| Error::KeyStore(format!("keyfile {} create : {:?}", name, e)))?;
        key.write(&mut file)
            .map_err(|e| Error::KeyStore(format!("keyfile {} write : {:?}", name, e)))?;
        Ok(())
    }

    fn load_from_file(&self, name: &str) -> Result<KeyFile> {
        let file_name = format!("{}/{}.json", self.keys_dir_path, name);
        let file = File::open(file_name)
            .map_err(|e| Error::KeyStore(format!("keyfile {} open : {:?}", name, e)))?;
        let key = KeyFile::load(&file)
            .map_err(|e| Error::KeyStore(format!("keyfile {} load : {:?}", name, e)))?;
        Ok(key)
    }

    pub fn get_new_address(
        &self,
        name: Option<&str>,
        password: Option<&str>,
        curve_type: Option<CryptoTypeId>,
        address_format: Option<Ss58AddressFormat>,
        words: Option<usize>,
    ) -> Result<String> {
        // generate random keypair
        let words = words.unwrap_or(12);
        let mnemonic_type = MnemonicType::for_word_count(words).map_err(|e| {
            Error::KeyStore(format!(
                "Invalid number of words given for phrase: must be 12/15/18/21/24 : {}",
                e
            ))
        })?;
        let mnemonic = Mnemonic::new(mnemonic_type, Language::English);
        let phrase = mnemonic.phrase();

        // save
        self.import_new_address(name, password, curve_type, address_format, phrase)
    }

    pub fn import_new_address(
        &self,
        name: Option<&str>,
        password: Option<&str>,
        curve_type: Option<CryptoTypeId>,
        address_format: Option<Ss58AddressFormat>,
        phrase: &str,
    ) -> Result<String> {
        let curve_type = curve_type.unwrap_or(ed25519::CRYPTO_ID);

        // TODO
        let (pair, _) = <Ed25519 as Crypto>::Pair::from_phrase(phrase, password)
            .map_err(|e| Error::KeyStore(format!("Invalid phrase : {:?}", e)))?;

        let address_formt = address_format.unwrap_or_default();

        let address = pair.public().to_ss58check_with_version(address_formt);

        let name = name.unwrap_or(&address);

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

        self.save_to_file(name, &key)?;
        Ok(name.to_string())
    }

    pub fn export_address(&self, name: &str, password: Option<&str>) -> Result<Account> {
        let key = self.load_from_file(name)?;

        let password = Password::from(password.unwrap_or("").to_string());
        let secret = key
            .crypto
            .decrypt(&password)
            .map_err(|e| Error::KeyStore(format!("Invalid password : {}", e)))?;

        let phrase = String::from_utf8(secret)
            .map_err(|e| Error::KeyStore(format!("Convert secret : {}", e)))?;

        // let seed = Mnemonic::from_phrase(phrase, lang: Language)

        Ok(Account {
            secret_phrase: phrase.clone(),
            secret_seed: "".to_string(),
            public_key: "".to_string(),
            ss58_address: key.address.clone(),
            name: name.to_string(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn get_new_address() {
        let ks = KeyStore::new(None);
        let ret = ks.get_new_address(None, None, None, None, None);
        println!("===={:?}", ret);
    }

    #[test]
    fn import_new_address() {
        let phrase = "romance bus jealous account when lunch crush clinic ugly text shrug waste";
        let ks = KeyStore::new(None);
        let ret = ks.import_new_address(Some("sss"), None, None, None, phrase);
        println!("===={:?}", ret);
    }

    #[test]
    fn export_address() {
        let ks = KeyStore::new(None);
        let ret = ks.export_address("sss", None);
        println!("===={:?}", ret);
    }
}
