use bip39::{Language, Mnemonic, MnemonicType, Seed as BIPSeed};
use parity_scale_codec::{Decode, Encode};
use schnorrkel::keys::{MINI_SECRET_KEY_LENGTH, SECRET_KEY_LENGTH};
use schnorrkel::{
    derive::{ChainCode, Derivation, CHAIN_CODE_LENGTH},
    signing_context, ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;

use super::crypto::{
    CryptoType, CryptoTypeId, Derive, DeriveJunction, Pair as TraitPair, Public as TraitPublic,
    PublicError, SecretStringError, Ss58Codec,
};
use super::hexdisplay::HexDisplay;

const SIGNING_CTX: &[u8] = b"key";

/// An identifier used to match public keys against sr25519 keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"sr25");

/// The raw secret seed, which can be used to recreate the `Pair`.
type Seed = [u8; MINI_SECRET_KEY_LENGTH];

/// An Schnorrkel/Ristretto x25519 ("sr25519") public key.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Decode, Default)]
pub struct Public(pub [u8; 32]);

impl AsRef<[u8; 32]> for Public {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Public {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for Public {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl std::ops::Deref for Public {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Public> for [u8; 32] {
    fn from(x: Public) -> [u8; 32] {
        x.0
    }
}

impl std::str::FromStr for Public {
    type Err = PublicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ss58check(s)
    }
}

impl std::convert::TryFrom<&[u8]> for Public {
    type Error = PublicError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == 32 {
            let mut inner = [0u8; 32];
            inner.copy_from_slice(data);
            Ok(Public(inner))
        } else {
            Err(PublicError::BadLength)
        }
    }
}

impl std::fmt::Display for Public {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_ss58check())
    }
}

impl std::fmt::Debug for Public {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = self.to_ss58check();
        write!(f, "{} ({}...)", HexDisplay::from(&self.0), &s[0..8])
    }
}

impl Serialize for Public {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_ss58check())
    }
}

impl<'de> Deserialize<'de> for Public {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Public::from_ss58check(&String::deserialize(deserializer)?)
            .map_err(|e| de::Error::custom(format!("{:?}", e)))
    }
}

impl Derive for Public {
    /// Derive a child key from a series of given junctions.
    ///
    /// `None` if there are any hard junctions in there.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(&self, path: Iter) -> Option<Public> {
        let mut acc = PublicKey::from_bytes(self.as_ref()).ok()?;
        for j in path {
            match j {
                DeriveJunction::Soft(cc) => acc = acc.derived_key_simple(ChainCode(cc), &[]).0,
                DeriveJunction::Hard(_cc) => return None,
            }
        }
        Some(Self(acc.to_bytes()))
    }
}

impl Public {
    /// A new instance from the given 32-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    pub fn from_raw(data: [u8; 32]) -> Self {
        Public(data)
    }

    /// Return a slice filled with raw data.
    pub fn as_array_ref(&self) -> &[u8; 32] {
        self.as_ref()
    }
}

impl TraitPublic for Public {
    /// A new instance from the given slice that should be 32 bytes long.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    fn from_slice(data: &[u8]) -> Self {
        let mut r = [0u8; 32];
        r.copy_from_slice(data);
        Public(r)
    }
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") key pair.
pub struct Pair(Keypair);

impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair(schnorrkel::Keypair {
            public: self.0.public,
            secret: schnorrkel::SecretKey::from_bytes(&self.0.secret.to_bytes()[..])
                .expect("key is always the correct size; qed"),
        })
    }
}

impl From<MiniSecretKey> for Pair {
    fn from(sec: MiniSecretKey) -> Pair {
        Pair(sec.expand_to_keypair(ExpansionMode::Ed25519))
    }
}

impl From<SecretKey> for Pair {
    fn from(sec: SecretKey) -> Pair {
        Pair(Keypair::from(sec))
    }
}

impl From<schnorrkel::Keypair> for Pair {
    fn from(p: schnorrkel::Keypair) -> Pair {
        Pair(p)
    }
}

impl From<Pair> for schnorrkel::Keypair {
    fn from(p: Pair) -> schnorrkel::Keypair {
        p.0
    }
}

impl AsRef<schnorrkel::Keypair> for Pair {
    fn as_ref(&self) -> &schnorrkel::Keypair {
        &self.0
    }
}

/// Derive a single hard junction.
fn derive_hard_junction(secret: &SecretKey, cc: &[u8; CHAIN_CODE_LENGTH]) -> MiniSecretKey {
    secret
        .hard_derive_mini_secret_key(Some(ChainCode(cc.clone())), b"")
        .0
}

#[derive(Debug)]
pub enum DeriveError {}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = Seed;
    type Signature = Signature;
    type DeriveError = DeriveError;

    /// Make a new key pair from raw secret seed material.
    ///
    /// This is generated using schnorrkel's Mini-Secret-Keys.
    ///
    /// A MiniSecretKey is literally what Ed25519 calls a SecretKey, which is just 32 random bytes.
    fn from_seed(seed: &Seed) -> Pair {
        Self::from_seed_slice(&seed[..]).expect("32 bytes can always build a key; qed")
    }

    /// Get the public key.
    fn public(&self) -> Public {
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&self.0.public.to_bytes());
        Public(pk)
    }

    /// Make a new key pair from secret seed material. The slice must be 32 bytes long or it
    /// will return `None`.
    ///
    /// You should never need to use this; generate(), generate_with_phrase(), from_phrase()
    fn from_seed_slice(seed: &[u8]) -> Result<Pair, SecretStringError> {
        match seed.len() {
            MINI_SECRET_KEY_LENGTH => Ok(Pair(
                MiniSecretKey::from_bytes(seed)
                    .map_err(|_| SecretStringError::InvalidSeed)?
                    .expand_to_keypair(ExpansionMode::Ed25519),
            )),
            SECRET_KEY_LENGTH => Ok(Pair(
                SecretKey::from_bytes(seed)
                    .map_err(|_| SecretStringError::InvalidSeed)?
                    .to_keypair(),
            )),
            _ => Err(SecretStringError::InvalidSeedLength),
        }
    }

    fn generate_with_phrase(password: Option<&str>) -> (Pair, String, Seed) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase();
        let (pair, seed) = Self::from_phrase(phrase, password)
            .expect("All phrases generated by Mnemonic are valid; qed");
        (pair, phrase.to_owned(), seed)
    }

    fn from_phrase(
        phrase: &str,
        password: Option<&str>,
    ) -> Result<(Pair, Seed), SecretStringError> {
        Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| SecretStringError::InvalidPhrase)
            .map(|m| Self::from_entropy(m.entropy(), password))
    }

    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), Self::DeriveError> {
        let seed = if let Some(s) = seed {
            if let Ok(msk) = MiniSecretKey::from_bytes(&s) {
                if msk.expand(ExpansionMode::Ed25519) == self.0.secret {
                    Some(msk)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let init = self.0.secret.clone();
        let (result, seed) = path.fold((init, seed), |(acc, acc_seed), j| match (j, acc_seed) {
            (DeriveJunction::Soft(cc), _) => (acc.derived_key_simple(ChainCode(cc), &[]).0, None),
            (DeriveJunction::Hard(cc), maybe_seed) => {
                let seed = derive_hard_junction(&acc, &cc);
                (
                    seed.expand(ExpansionMode::Ed25519),
                    maybe_seed.map(|_| seed),
                )
            }
        });
        Ok((
            Self(result.into()),
            seed.map(|s| MiniSecretKey::to_bytes(&s)),
        ))
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let context = signing_context(SIGNING_CTX);
        self.0.sign(context.bytes(message)).into()
    }

    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        Self::verify_weak(&sig.0[..], message, pubkey)
    }

    fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig: &[u8], message: M, pubkey: P) -> bool {
        let signature = match schnorrkel::Signature::from_bytes(sig) {
            Ok(signature) => signature,
            Err(_) => return false,
        };

        let pub_key = match PublicKey::from_bytes(pubkey.as_ref()) {
            Ok(pub_key) => pub_key,
            Err(_) => return false,
        };

        pub_key
            .verify_simple(SIGNING_CTX, message.as_ref(), &signature)
            .is_ok()
    }

    fn to_raw_vec(&self) -> Vec<u8> {
        self.0.secret.to_bytes().to_vec()
    }
}

impl Pair {
    /// Make a new key pair from binary data derived from a valid seed phrase.
    ///
    /// This uses a key derivation function to convert the entropy into a seed, then returns
    /// the pair generated from it.
    pub fn from_entropy(entropy: &[u8], password: Option<&str>) -> (Pair, Seed) {
        let mini_secret_from_entropy =
            |entropy: &[u8], password: &str| -> Result<MiniSecretKey, SecretStringError> {
                let mnemonic = Mnemonic::from_entropy(entropy, Language::English)
                    .map_err(|_| SecretStringError::InvalidPhrase)?;
                let seed = BIPSeed::new(&mnemonic, password);
                MiniSecretKey::from_bytes(&seed.as_bytes()[..32])
                    .map_err(|_| SecretStringError::InvalidPhrase)
            };

        let mini_key: MiniSecretKey = mini_secret_from_entropy(entropy, password.unwrap_or(""))
            .expect("32 bytes can always build a key; qed");

        let kp = mini_key.expand_to_keypair(ExpansionMode::Ed25519);
        (Pair(kp), mini_key.to_bytes())
    }

    /// Verify a signature on a message. Returns `true` if the signature is good.
    /// Supports old 0.1.1 deprecated signatures and should be used only for backward
    /// compatibility.
    pub fn verify_deprecated<M: AsRef<[u8]>>(sig: &Signature, message: M, pubkey: &Public) -> bool {
        // Match both schnorrkel 0.1.1 and 0.8.0+ signatures, supporting both wallets
        // that have not been upgraded and those that have.
        match PublicKey::from_bytes(pubkey.as_ref()) {
            Ok(pk) => pk
                .verify_simple_preaudit_deprecated(SIGNING_CTX, message.as_ref(), &sig.0[..])
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// An Schnorrkel/Ristretto x25519 ("sr25519") signature.
///
/// Instead of importing it for the local module, alias it to be available as a public type
#[derive(Encode, Decode)]
pub struct Signature(pub [u8; 64]);

impl std::convert::TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == 64 {
            let mut inner = [0u8; 64];
            inner.copy_from_slice(data);
            Ok(Signature(inner))
        } else {
            Err(())
        }
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self))
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signature_hex = hex::decode(&String::deserialize(deserializer)?)
            .map_err(|e| de::Error::custom(format!("{:?}", e)))?;
        Ok(Signature::try_from(signature_hex.as_ref())
            .map_err(|e| de::Error::custom(format!("{:?}", e)))?)
    }
}

impl Clone for Signature {
    fn clone(&self) -> Self {
        let mut r = [0u8; 64];
        r.copy_from_slice(&self.0[..]);
        Signature(r)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 64])
    }
}

impl PartialEq for Signature {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl Eq for Signature {}

impl From<Signature> for [u8; 64] {
    fn from(v: Signature) -> [u8; 64] {
        v.0
    }
}

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl From<schnorrkel::Signature> for Signature {
    fn from(s: schnorrkel::Signature) -> Signature {
        Signature(s.to_bytes())
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", HexDisplay::from(&self.0))
    }
}

/// A localized signature also contains sender information.
/// NOTE: Encode and Decode traits are supported in ed25519 but not possible for now here.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LocalizedSignature {
    /// The signer of the signature.
    pub signer: Public,
    /// The signature itself.
    pub signature: Signature,
}

impl Signature {
    /// A new instance from the given 64-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real signature. Only use
    /// it if you are certain that the array actually is a signature, or if you
    /// immediately verify the signature.  All functions that verify signatures
    /// will fail if the `Signature` is not actually a valid signature.
    pub fn from_raw(data: [u8; 64]) -> Signature {
        Signature(data)
    }

    /// A new instance from the given slice that should be 64 bytes long.
    ///
    /// NOTE: No checking goes on to ensure this is a real signature. Only use it if
    /// you are certain that the array actually is a signature. GIGO!
    pub fn from_slice(data: &[u8]) -> Self {
        let mut r = [0u8; 64];
        r.copy_from_slice(data);
        Signature(r)
    }
}

impl CryptoType for Public {
    type Pair = Pair;
}

impl CryptoType for Signature {
    type Pair = Pair;
}

impl CryptoType for Pair {
    type Pair = Pair;
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use serde_json;

    #[test]
    fn derive_soft_should_work() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let derive_1 = pair
            .derive(Some(DeriveJunction::soft(1)).into_iter(), None)
            .unwrap()
            .0;
        let derive_1b = pair
            .derive(Some(DeriveJunction::soft(1)).into_iter(), None)
            .unwrap()
            .0;
        let derive_2 = pair
            .derive(Some(DeriveJunction::soft(2)).into_iter(), None)
            .unwrap()
            .0;
        assert_eq!(derive_1.public(), derive_1b.public());
        assert_ne!(derive_1.public(), derive_2.public());
    }

    #[test]
    fn derive_hard_should_work() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let derive_1 = pair
            .derive(Some(DeriveJunction::hard(1)).into_iter(), None)
            .unwrap()
            .0;
        let derive_1b = pair
            .derive(Some(DeriveJunction::hard(1)).into_iter(), None)
            .unwrap()
            .0;
        let derive_2 = pair
            .derive(Some(DeriveJunction::hard(2)).into_iter(), None)
            .unwrap()
            .0;
        assert_eq!(derive_1.public(), derive_1b.public());
        assert_ne!(derive_1.public(), derive_2.public());
    }

    #[test]
    fn derive_soft_public_should_work() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let path = Some(DeriveJunction::soft(1));
        let pair_1 = pair.derive(path.clone().into_iter(), None).unwrap().0;
        let public_1 = pair.public().derive(path.into_iter()).unwrap();
        assert_eq!(pair_1.public(), public_1);
    }

    #[test]
    fn derive_hard_public_should_fail() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let path = Some(DeriveJunction::hard(1));
        assert!(pair.public().derive(path.into_iter()).is_none());
    }

    #[test]
    fn sr_test_vector_should_work() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let public = pair.public();
        assert_eq!(
            public,
            Public::from_raw(hex!(
                "44a996beb1eef7bdcab976ab6d2ca26104834164ecf28fb375600576fcc6eb0f"
            ))
        );
        let message = b"";
        let signature = pair.sign(message);
        assert!(Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn generated_pair_should_work() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let message = b"Something important";
        let signature = pair.sign(&message[..]);
        assert!(Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn messed_signature_should_not_work() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let message = b"Signed payload";
        let Signature(mut bytes) = pair.sign(&message[..]);
        bytes[0] = !bytes[0];
        bytes[2] = !bytes[2];
        let signature = Signature(bytes);
        assert!(!Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn messed_message_should_not_work() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let message = b"Something important";
        let signature = pair.sign(&message[..]);
        assert!(!Pair::verify(
            &signature,
            &b"Something unimportant",
            &public
        ));
    }

    #[test]
    fn seeded_pair_should_work() {
        let pair = Pair::from_seed(b"12345678901234567890123456789012");
        let public = pair.public();
        assert_eq!(
            public,
            Public::from_raw(hex!(
                "741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63"
            ))
        );
        let message = hex!("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee00000000000000000200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a4500000000000000");
        let signature = pair.sign(&message[..]);
        assert!(Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn ss58check_roundtrip_works() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let s = public.to_ss58check();
        println!("Correct: {}", s);
        let cmp = Public::from_ss58check(&s).unwrap();
        assert_eq!(cmp, public);
    }

    #[test]
    fn signature_serialization_works() {
        let pair = Pair::from_seed(b"12345678901234567890123456789012");
        let message = b"Something important";
        let signature = pair.sign(&message[..]);
        let serialized_signature = serde_json::to_string(&signature).unwrap();
        // Signature is 64 bytes, so 128 chars + 2 quote chars
        assert_eq!(serialized_signature.len(), 130);
        let signature = serde_json::from_str(&serialized_signature).unwrap();
        assert!(Pair::verify(&signature, &message[..], &pair.public()));
    }
}
