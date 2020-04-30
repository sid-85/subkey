#[macro_use]
extern crate lazy_static;

pub mod crypto;
pub mod keystore;

use serde_json::json;

use crypto::{crypto::*, ecdsa, ed25519, sr25519, hexdisplay::HexDisplay};

pub struct Ed25519;
impl Crypto for Ed25519 {
    type Pair = ed25519::Pair;
    type Public = ed25519::Public;

    fn pair_from_suri(suri: &str, password_override: Option<&str>) -> Self::Pair {
        ed25519::Pair::from_legacy_string(suri, password_override)
    }
}

pub struct Sr25519;
impl Crypto for Sr25519 {
    type Pair = sr25519::Pair;
    type Public = sr25519::Public;
}

pub struct Ecdsa;
impl Crypto for Ecdsa {
    type Pair = ecdsa::Pair;
    type Public = ecdsa::Public;

    fn pair_from_suri(suri: &str, password_override: Option<&str>) -> Self::Pair {
        ecdsa::Pair::from_legacy_string(suri, password_override)
    }
}

pub trait Crypto: Sized {
    type Pair: Pair<Public = Self::Public>;
    type Public: Public + Ss58Codec + AsRef<[u8]>;

    fn ss58_from_pair(pair: &Self::Pair, version: Option<Ss58AddressFormat>) -> String {
        let v = version.unwrap_or_default();
        pair.public().to_ss58check_with_version(v)
    }

    fn public_from_pair(pair: &Self::Pair) -> Self::Public {
        pair.public()
    }

    fn pair_from_suri(suri: &str, password: Option<&str>) -> Self::Pair {
        Self::Pair::from_string(suri, password).expect("Invalid phrase")
    }

    fn print_from_uri(
        uri: &str,
        password: Option<&str>,
        version: Option<Ss58AddressFormat>,
    ) {
        if let Ok((pair, seed)) = Self::Pair::from_phrase(uri, password) {
            let public_key = Self::public_from_pair(&pair);
            let json = json!({
                "secretPhrase": uri,
                "secretSeed": format_seed::<Self>(seed),
                "publicKey": format_public_key::<Self>(public_key.clone()),
                "ss58Address": Self::ss58_from_pair(&pair, version),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Json pretty print failed")
            );
        } else if let Ok((pair, seed)) = Self::Pair::from_string_with_seed(uri, password) {
            let public_key = Self::public_from_pair(&pair);
            let json = json!({
                "secretKeyUri": uri,
                "secretSeed": if let Some(seed) = seed { format_seed::<Self>(seed) } else { "n/a".into() },
                "publicKey": format_public_key::<Self>(public_key.clone()),
                "ss58Address": Self::ss58_from_pair(&pair, version),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Json pretty print failed")
            );
        } else if let Ok((public_key, v)) =
            <Self::Pair as Pair>::Public::from_string_with_version(uri)
        {
            let json = json!({
                "publicKeyUri": uri,
                "networkId": String::from(v),
                "publicKey": format_public_key::<Self>(public_key.clone()),
                "ss58Address": public_key.to_ss58check_with_version(version.unwrap_or_default()),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Json pretty print failed")
            );
        } else {
            eprintln!("Invalid phrase/URI given");
        }
    }
}

pub type SignatureOf<C> = <<C as Crypto>::Pair as Pair>::Signature;
pub type PublicOf<C> = <<C as Crypto>::Pair as Pair>::Public;
pub type SeedOf<C> = <<C as Crypto>::Pair as Pair>::Seed;

pub fn format_signature<C: Crypto>(signature: &SignatureOf<C>) -> String {
	format!("{}", HexDisplay::from(&signature.as_ref()))
}

pub fn format_seed<C: Crypto>(seed: SeedOf<C>) -> String {
	format!("0x{}", HexDisplay::from(&seed.as_ref()))
}

pub fn format_public_key<C: Crypto>(public_key: PublicOf<C>) -> String {
	format!("0x{}", HexDisplay::from(&public_key.as_ref()))
}
