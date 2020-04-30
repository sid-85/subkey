use bip39::{Language, Mnemonic, MnemonicType, Seed as BIPSeed};
use parity_scale_codec::{Decode, Encode};
use secp256k1::{PublicKey, SecretKey};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    cmp::Ordering,
    convert::{TryFrom, TryInto},
};

use super::crypto::{
    CryptoType, CryptoTypeId, Derive, DeriveJunction, Pair as TraitPair, Public as TraitPublic,
    PublicError, SecretStringError, Ss58Codec,
};
use super::hashing::blake2_256;
use super::hexdisplay::HexDisplay;

/// An identifier used to match public keys against ecdsa keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"ecds");

/// A secret seed (which is bytewise essentially equivalent to a SecretKey).
///
/// We need it as a different type because `Seed` is expected to be AsRef<[u8]>.
type Seed = [u8; 32];

/// The ECDSA compressed public key.
#[derive(Clone)]
pub struct Public([u8; 33]);

impl PartialEq for Public {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for Public {}

impl PartialOrd for Public {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Public {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_ref().cmp(&other.as_ref())
    }
}

impl Default for Public {
    fn default() -> Self {
        Public([0u8; 33])
    }
}

impl Derive for Public {}

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
        if data.len() == 33 {
            Ok(Self::from_slice(data))
        } else {
            Err(PublicError::BadLength)
        }
    }
}

impl From<Public> for [u8; 33] {
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
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = self.to_ss58check();
        write!(f, "{} ({}...)", HexDisplay::from(&self.as_ref()), &s[0..8])
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
    /// A new instance from the given 33-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    pub fn from_raw(data: [u8; 33]) -> Self {
        Self(data)
    }

    /// Create a new instance from the given full public key.
    ///
    /// This will convert the full public key into the compressed format.
    pub fn from_full(full: &[u8]) -> Result<Self, ()> {
        secp256k1::PublicKey::parse_slice(full, None)
            .map(|k| k.serialize_compressed())
            .map(Self)
            .map_err(|_| ())
    }
}

impl TraitPublic for Public {
    /// A new instance from the given slice that should be 33 bytes long.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    fn from_slice(data: &[u8]) -> Self {
        let mut r = [0u8; 33];
        r.copy_from_slice(data);
        Self(r)
    }
}

/// A key pair.
#[derive(Clone)]
pub struct Pair {
    public: PublicKey,
    secret: SecretKey,
}

/// Derive a single hard junction.
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
    ("Secp256k1HDKD", secret_seed, cc).using_encoded(|data| blake2_256(data))
}

/// An error when deriving a key.
pub enum DeriveError {
    /// A soft key was found in the path (and is unsupported).
    SoftKeyInPath,
}

impl Pair {
    /// Get the seed for this key.
    pub fn seed(&self) -> Seed {
        self.secret.serialize()
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
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English)
            .map_err(|_| SecretStringError::InvalidPhrase)?;
        let big_seed = BIPSeed::new(&mnemonic, password.unwrap_or(""));
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
        let secret =
            SecretKey::parse_slice(seed_slice).map_err(|_| SecretStringError::InvalidSeedLength)?;
        let public = PublicKey::from_secret_key(&secret);
        Ok(Pair { secret, public })
    }

    /// Derive a child key from a series of given junctions.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        _seed: Option<Seed>,
    ) -> Result<(Pair, Option<Seed>), DeriveError> {
        let mut acc = self.secret.serialize();
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
        Public(self.public.serialize_compressed())
    }

    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Signature {
        let message = secp256k1::Message::parse(&blake2_256(message));
        secp256k1::sign(&message, &self.secret).into()
    }

    /// Verify a signature on a message. Returns true if the signature is good.
    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool {
        let message = secp256k1::Message::parse(&blake2_256(message.as_ref()));
        let sig: (_, _) = match sig.try_into() {
            Ok(x) => x,
            _ => return false,
        };
        match secp256k1::recover(&message, &sig.0, &sig.1) {
            Ok(actual) => &pubkey.0[..] == &actual.serialize_compressed()[..],
            _ => false,
        }
    }

    /// Verify a signature on a message. Returns true if the signature is good.
    ///
    /// This doesn't use the type system to ensure that `sig` and `pubkey` are the correct
    /// size. Use it only if you're coming from byte buffers and need the speed.
    fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig: &[u8], message: M, pubkey: P) -> bool {
        let message = secp256k1::Message::parse(&blake2_256(message.as_ref()));
        if sig.len() != 65 {
            return false;
        }
        let ri = match secp256k1::RecoveryId::parse(sig[64]) {
            Ok(x) => x,
            _ => return false,
        };
        let sig = match secp256k1::Signature::parse_slice(&sig[0..64]) {
            Ok(x) => x,
            _ => return false,
        };
        match secp256k1::recover(&message, &sig, &ri) {
            Ok(actual) => pubkey.as_ref() == &actual.serialize()[1..],
            _ => false,
        }
    }

    /// Return a vec filled with raw data.
    fn to_raw_vec(&self) -> Vec<u8> {
        self.seed().to_vec()
    }
}

/// A signature (a 512-bit value, plus 8 bits for recovery ID).
#[derive(Encode, Decode)]
pub struct Signature([u8; 65]);

impl std::convert::TryFrom<&[u8]> for Signature {
    type Error = ();

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() == 65 {
            let mut inner = [0u8; 65];
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
        let mut r = [0u8; 65];
        r.copy_from_slice(&self.0[..]);
        Signature(r)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 65])
    }
}

impl PartialEq for Signature {
    fn eq(&self, b: &Self) -> bool {
        self.0[..] == b.0[..]
    }
}

impl Eq for Signature {}

impl From<Signature> for [u8; 65] {
    fn from(v: Signature) -> [u8; 65] {
        v.0
    }
}

impl AsRef<[u8; 65]> for Signature {
    fn as_ref(&self) -> &[u8; 65] {
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
    /// A new instance from the given 65-byte `data`.
    ///
    /// NOTE: No checking goes on to ensure this is a real signature. Only use it if
    /// you are certain that the array actually is a signature. GIGO!
    pub fn from_raw(data: [u8; 65]) -> Signature {
        Signature(data)
    }

    /// A new instance from the given slice that should be 65 bytes long.
    ///
    /// NOTE: No checking goes on to ensure this is a real signature. Only use it if
    /// you are certain that the array actually is a signature. GIGO!
    pub fn from_slice(data: &[u8]) -> Self {
        let mut r = [0u8; 65];
        r.copy_from_slice(data);
        Signature(r)
    }

    /// Recover the public key from this signature and a message.
    pub fn recover<M: AsRef<[u8]>>(&self, message: M) -> Option<Public> {
        let message = secp256k1::Message::parse(&blake2_256(message.as_ref()));
        let sig: (_, _) = self.try_into().ok()?;
        secp256k1::recover(&message, &sig.0, &sig.1)
            .ok()
            .map(|recovered| Public(recovered.serialize_compressed()))
    }
}

impl From<(secp256k1::Signature, secp256k1::RecoveryId)> for Signature {
    fn from(x: (secp256k1::Signature, secp256k1::RecoveryId)) -> Signature {
        let mut r = Self::default();
        r.0[0..64].copy_from_slice(&x.0.serialize()[..]);
        r.0[64] = x.1.serialize();
        r
    }
}

impl<'a> TryFrom<&'a Signature> for (secp256k1::Signature, secp256k1::RecoveryId) {
    type Error = ();
    fn try_from(
        x: &'a Signature,
    ) -> Result<(secp256k1::Signature, secp256k1::RecoveryId), Self::Error> {
        Ok((
            secp256k1::Signature::parse_slice(&x.0[0..64]).expect("hardcoded to 64 bytes; qed"),
            secp256k1::RecoveryId::parse(x.0[64]).map_err(|_| ())?,
        ))
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
    fn seed_and_derive_should_work() {
        let seed = hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let pair = Pair::from_seed(&seed);
        assert_eq!(pair.seed(), seed);
        let path = vec![DeriveJunction::Hard([0u8; 32])];
        let derived = pair.derive(path.into_iter(), None).ok().unwrap();
        assert_eq!(
            derived.0.seed(),
            hex!("b8eefc4937200a8382d00050e050ced2d4ab72cc2ef1b061477afb51564fdd61")
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
			Public::from_full(
				&hex!("8db55b05db86c0b1786ca49f095d76344c9e6056b2f02701a7e7f3c20aabfd913ebbe148dd17c56551a52952371071a6c604b3f3abe8f2c8fa742158ea6dd7d4")[..],
			).unwrap(),
		);
        let message = b"";
        let signature = hex!("3dde91174bd9359027be59a428b8146513df80a2a3c7eda2194f64de04a69ab97b753169e94db6ffd50921a2668a48b94ca11e3d32c1ff19cfe88890aa7e8f3c00");
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
			Public::from_full(
				&hex!("8db55b05db86c0b1786ca49f095d76344c9e6056b2f02701a7e7f3c20aabfd913ebbe148dd17c56551a52952371071a6c604b3f3abe8f2c8fa742158ea6dd7d4")[..],
			).unwrap(),
		);
        let message = b"";
        let signature = hex!("3dde91174bd9359027be59a428b8146513df80a2a3c7eda2194f64de04a69ab97b753169e94db6ffd50921a2668a48b94ca11e3d32c1ff19cfe88890aa7e8f3c00");
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
			Public::from_full(
				&hex!("5676109c54b9a16d271abeb4954316a40a32bcce023ac14c8e26e958aa68fba995840f3de562156558efbfdac3f16af0065e5f66795f4dd8262a228ef8c6d813")[..],
			).unwrap(),
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
        // Signature is 65 bytes, so 130 chars + 2 quote chars
        assert_eq!(serialized_signature.len(), 132);
        let signature = serde_json::from_str(&serialized_signature).unwrap();
        assert!(Pair::verify(&signature, &message[..], &pair.public()));
    }
}
