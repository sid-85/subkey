use bip39::{Language, Mnemonic, MnemonicType, Seed as BIPSeed};
use ed25519_dalek;
use parity_scale_codec::{Decode, Encode};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;

use super::crypto::{
    CryptoType, CryptoTypeId, Derive, DeriveJunction, Pair as TraitPair, Public as TraitPublic,
    PublicError, SecretStringError, Ss58Codec,
};
use super::hexdisplay::HexDisplay;

/// An identifier used to match public keys against ed25519 keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"ed25");

/// A secret seed. It's not called a "secret key" because ring doesn't expose the secret keys
/// of the key pair (yeah, dumb); as such we're forced to remember the seed manually if we
/// will need it later (such as for HDKD).
type Seed = [u8; 32];

/// A public key.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Encode, Decode, Default)]
pub struct Public(pub [u8; 32]);

impl Derive for Public {}

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

impl From<Public> for [u8; 32] {
    fn from(x: Public) -> Self {
        x.0
    }
}

impl From<Pair> for Public {
    fn from(x: Pair) -> Self {
        x.public()
    }
}

impl std::str::FromStr for Public {
    type Err = PublicError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_ss58check(s)
    }
}

impl std::fmt::Display for Public {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_ss58check())
    }
}

impl std::fmt::Debug for Public {
    #[cfg(feature = "std")]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = self.to_ss58check();
        write!(
            f,
            "{} ({}...)",
            crate::hexdisplay::HexDisplay::from(&self.0),
            &s[0..8]
        )
    }

    #[cfg(not(feature = "std"))]
    fn fmt(&self, _: &mut std::fmt::Formatter) -> std::fmt::Result {
        Ok(())
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

/// A key pair.
pub struct Pair(ed25519_dalek::Keypair);

impl Clone for Pair {
    fn clone(&self) -> Self {
        Pair(ed25519_dalek::Keypair {
            public: self.0.public.clone(),
            secret: ed25519_dalek::SecretKey::from_bytes(self.0.secret.as_bytes())
                .expect("key is always the correct size; qed"),
        })
    }
}

/// Derive a single hard junction.
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
    ("Ed25519HDKD", secret_seed, cc).using_encoded(|data| {
        let mut res = [0u8; 32];
        res.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
        res
    })
}

/// An error when deriving a key.
pub enum DeriveError {
    /// A soft key was found in the path (and is unsupported).
    SoftKeyInPath,
}

impl Pair {
    /// Get the seed for this key.
    pub fn seed(&self) -> &Seed {
        self.0.secret.as_bytes()
    }

    /// Exactly as `from_string` except that if no matches are found then, the the first 32
    /// characters are taken (padded with spaces as necessary) and used as the MiniSecretKey.
    pub fn from_legacy_string(s: &str, password_override: Option<&str>) -> Pair {
        Self::from_string(s, password_override).unwrap_or_else(|_| {
            let mut padded_seed: Seed = [' ' as u8; 32];
            let len = s.len().min(32);
            padded_seed[..len].copy_from_slice(&s.as_bytes()[..len]);
            Self::from_seed(&padded_seed)
        })
    }
}

impl TraitPair for Pair {
    type Public = Public;
    type Seed = Seed;
    type Signature = Signature;
    type DeriveError = DeriveError;

    /// Generate new secure (random) key pair and provide the recovery phrase.
    ///
    /// You can recover the same key later with `from_phrase`.
    fn generate_with_phrase(password: Option<&str>) -> (Pair, String, Seed) {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase();
        let (pair, seed) = Self::from_phrase(phrase, password)
            .expect("All phrases generated by Mnemonic are valid; qed");
        (pair, phrase.to_owned(), seed)
    }

    /// Generate key pair from given recovery phrase and password.
    fn from_phrase(
        phrase: &str,
        password: Option<&str>,
    ) -> Result<(Pair, Seed), SecretStringError> {
        let big_seed = BIPSeed::new(
            &Mnemonic::from_phrase(phrase, Language::English)
                .map_err(|_| SecretStringError::InvalidPhrase)?,
            password.unwrap_or(""),
        );
        let mut seed = Seed::default();
        seed.copy_from_slice(&big_seed.as_bytes()[0..32]);
        Self::from_seed_slice(&big_seed.as_bytes()[0..32]).map(|x| (x, seed))
    }

    /// Make a new key pair from secret seed material.
    ///
    /// You should never need to use this; generate(), generate_with_phrase
    fn from_seed(seed: &Seed) -> Pair {
        Self::from_seed_slice(&seed[..]).expect("seed has valid length; qed")
    }

    /// Make a new key pair from secret seed material. The slice must be 32 bytes long or it
    /// will return `None`.
    ///
    /// You should never need to use this; generate(), generate_with_phrase
    fn from_seed_slice(seed_slice: &[u8]) -> Result<Pair, SecretStringError> {
        let secret = ed25519_dalek::SecretKey::from_bytes(seed_slice)
            .map_err(|_| SecretStringError::InvalidSeedLength)?;
        let public = ed25519_dalek::PublicKey::from(&secret);
        Ok(Pair(ed25519_dalek::Keypair { secret, public }))
    }

    /// Derive a child key from a series of given junctions.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), DeriveError> {
        let mut acc = self.0.secret.to_bytes();
        for j in path {
            match j {
                DeriveJunction::Soft(_cc) => return Err(DeriveError::SoftKeyInPath),
                DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
            }
        }
        Ok((Self::from_seed(&acc), Some(acc)))
    }

    /// Get the public key.
    fn public(&self) -> Public {
        let mut r = [0u8; 32];
        let pk = self.0.public.as_bytes();
        r.copy_from_slice(pk);
        Public(r)
    }

    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Signature {
        let r = self.0.sign(message).to_bytes();
        Signature::from_raw(r)
    }

    /// Verify a signature on a message. Returns true if the signature is good.
    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        Self::verify_weak(&sig.0[..], message.as_ref(), pubkey)
    }

    /// Verify a signature on a message. Returns true if the signature is good.
    ///
    /// This doesn't use the type system to ensure that `sig` and `pubkey` are the correct
    /// size. Use it only if you're coming from byte buffers and need the speed.
    fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig: &[u8], message: M, pubkey: P) -> bool {
        let public_key = match ed25519_dalek::PublicKey::from_bytes(pubkey.as_ref()) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match ed25519_dalek::Signature::from_bytes(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match public_key.verify(message.as_ref(), &sig) {
            Ok(_) => true,
            _ => false,
        }
    }

    /// Return a vec filled with raw data.
    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed().to_vec()
    }
}

/// A signature (a 512-bit value).
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

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", HexDisplay::from(&self.0))
    }
}

impl std::hash::Hash for Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.0[..], state);
    }
}

impl Signature {
    /// A new instance from the given 64-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real signature. Only use it if
    /// you are certain that the array actually is a signature. GIGO!
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

/// A localized signature also contains sender information.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct LocalizedSignature {
    /// The signer of the signature.
    pub signer: Public,
    /// The signature itself.
    pub signature: Signature,
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
    fn seed_and_derive_should_work() {
        let seed = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pair = Pair::from_seed(&seed);
        assert_eq!(pair.seed(), &seed);
        let path = vec![DeriveJunction::Hard([0u8; 32])];
        let derived = pair.derive(path.into_iter(), None).ok().unwrap().0;
        assert_eq!(
            derived.seed(),
            &hex!("ede3354e133f9c8e337ddd6ee5415ed4b4ffe5fc7d21e933f4930a3730e5b21c")
        );
    }

    #[test]
    fn test_vector_should_work() {
        let pair = Pair::from_seed(&hex!(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        ));
        let public = pair.public();
        assert_eq!(
            public,
            Public::from_raw(hex!(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            ))
        );
        let message = b"";
        let signature = hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let signature = Signature::from_raw(signature);
        assert!(&pair.sign(&message[..]) == &signature);
        assert!(Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn test_vector_by_string_should_work() {
        let pair = Pair::from_string(
            "0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            None,
        )
        .unwrap();
        let public = pair.public();
        assert_eq!(
            public,
            Public::from_raw(hex!(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            ))
        );
        let message = b"";
        let signature = hex!("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        let signature = Signature::from_raw(signature);
        assert!(&pair.sign(&message[..]) == &signature);
        assert!(Pair::verify(&signature, &message[..], &public));
    }

    #[test]
    fn generated_pair_should_work() {
        let (pair, _) = Pair::generate();
        let public = pair.public();
        let message = b"Something important";
        let signature = pair.sign(&message[..]);
        assert!(Pair::verify(&signature, &message[..], &public));
        assert!(!Pair::verify(&signature, b"Something else", &public));
    }

    #[test]
    fn seeded_pair_should_work() {
        let pair = Pair::from_seed(b"12345678901234567890123456789012");
        let public = pair.public();
        assert_eq!(
            public,
            Public::from_raw(hex!(
                "2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee"
            ))
        );
        let message = hex!("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee00000000000000000200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a4500000000000000");
        let signature = pair.sign(&message[..]);
        println!("Correct signature: {:?}", signature);
        assert!(Pair::verify(&signature, &message[..], &public));
        assert!(!Pair::verify(&signature, "Other message", &public));
    }

    #[test]
    fn generate_with_phrase_recovery_possible() {
        let (pair1, phrase, _) = Pair::generate_with_phrase(None);
        let (pair2, _) = Pair::from_phrase(&phrase, None).unwrap();

        assert_eq!(pair1.public(), pair2.public());
    }

    #[test]
    fn generate_with_password_phrase_recovery_possible() {
        let (pair1, phrase, _) = Pair::generate_with_phrase(Some("password"));
        let (pair2, _) = Pair::from_phrase(&phrase, Some("password")).unwrap();

        assert_eq!(pair1.public(), pair2.public());
    }

    #[test]
    fn password_does_something() {
        let (pair1, phrase, _) = Pair::generate_with_phrase(Some("password"));
        let (pair2, _) = Pair::from_phrase(&phrase, None).unwrap();

        assert_ne!(pair1.public(), pair2.public());
    }

    #[test]
    fn ss58check_roundtrip_works() {
        let pair = Pair::from_seed(b"12345678901234567890123456789012");
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
