use base58::{FromBase58, ToBase58};
use hex;
use parity_scale_codec::{Decode, Encode};
use rand::{rngs::OsRng, RngCore};
use regex::Regex;
use zeroize::Zeroize;

use std::convert::{TryFrom, TryInto};
use std::str;
use std::sync::Mutex;

use super::hexdisplay::HexDisplay;

/// A store for sensitive data.
///
/// Calls `Zeroize::zeroize` upon `Drop`.
#[derive(Clone)]
pub struct Protected<T: Zeroize>(T);

impl<T: Zeroize> AsRef<T> for Protected<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::ops::Deref for Protected<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> std::fmt::Debug for Protected<T> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "<protected>")
    }
}

impl<T: Zeroize> From<T> for Protected<T> {
    fn from(t: T) -> Self {
        Protected(t)
    }
}

impl<T: Zeroize> Zeroize for Protected<T> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

impl<T: Zeroize> Drop for Protected<T> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

/// The length of the junction identifier. Note that this is also referred to as the
/// `CHAIN_CODE_LENGTH` in the context of Schnorrkel.
pub const JUNCTION_ID_LEN: usize = 32;

/// A since derivation junction description. It is the single parameter used when creating
/// a new secret key from an existing secret key and, in the case of `SoftRaw` and `SoftIndex`
/// a new public key from an existing public key.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Encode, Decode)]
pub enum DeriveJunction {
    /// Soft (vanilla) derivation. Public keys have a correspondent derivation.
    Soft([u8; JUNCTION_ID_LEN]),
    /// Hard ("hardened") derivation. Public keys do not have a correspondent derivation.
    Hard([u8; JUNCTION_ID_LEN]),
}

impl DeriveJunction {
    /// Consume self to return a soft derive junction with the same chain code.
    pub fn soften(self) -> Self {
        DeriveJunction::Soft(self.unwrap_inner())
    }

    /// Consume self to return a hard derive junction with the same chain code.
    pub fn harden(self) -> Self {
        DeriveJunction::Hard(self.unwrap_inner())
    }

    /// Create a new soft (vanilla) DeriveJunction from a given, encodable, value.
    ///
    /// If you need a hard junction, use `hard()`.
    pub fn soft<T: Encode>(index: T) -> Self {
        let mut cc: [u8; JUNCTION_ID_LEN] = Default::default();
        index.using_encoded(|data| {
            if data.len() > JUNCTION_ID_LEN {
                let hash_result = blake2_rfc::blake2b::blake2b(JUNCTION_ID_LEN, &[], data);
                let hash = hash_result.as_bytes();
                cc.copy_from_slice(hash);
            } else {
                cc[0..data.len()].copy_from_slice(data);
            }
        });
        DeriveJunction::Soft(cc)
    }

    /// Create a new hard (hardened) DeriveJunction from a given, encodable, value.
    ///
    /// If you need a soft junction, use `soft()`.
    pub fn hard<T: Encode>(index: T) -> Self {
        Self::soft(index).harden()
    }

    /// Consume self to return the chain code.
    pub fn unwrap_inner(self) -> [u8; JUNCTION_ID_LEN] {
        match self {
            DeriveJunction::Hard(c) | DeriveJunction::Soft(c) => c,
        }
    }

    /// Get a reference to the inner junction id.
    pub fn inner(&self) -> &[u8; JUNCTION_ID_LEN] {
        match self {
            DeriveJunction::Hard(ref c) | DeriveJunction::Soft(ref c) => c,
        }
    }

    /// Return `true` if the junction is soft.
    pub fn is_soft(&self) -> bool {
        match *self {
            DeriveJunction::Soft(_) => true,
            _ => false,
        }
    }

    /// Return `true` if the junction is hard.
    pub fn is_hard(&self) -> bool {
        match *self {
            DeriveJunction::Hard(_) => true,
            _ => false,
        }
    }
}

impl<T: AsRef<str>> From<T> for DeriveJunction {
    fn from(j: T) -> DeriveJunction {
        let j = j.as_ref();
        let (code, hard) = if j.starts_with("'") {
            (&j[1..], true)
        } else {
            (j, false)
        };

        let res = if let Ok(n) = str::parse::<u64>(code) {
            // number
            DeriveJunction::soft(n)
        } else {
            // something else
            DeriveJunction::soft(code)
        };

        if hard {
            res.harden()
        } else {
            res
        }
    }
}

/// Derivable key trait.
pub trait Derive: Sized {
    /// Derive a child key from a series of given junctions.
    ///
    /// Will be `None` for public keys if there are any hard junctions in there.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(&self, _path: Iter) -> Option<Self> {
        None
    }
}

/// Trait suitable for typical cryptographic PKI key public type.
pub trait Public:
    AsRef<[u8]> + AsMut<[u8]> + Default + Derive + CryptoType + PartialEq + Eq + Clone + Send + Sync
{
    /// A new instance from the given slice.
    ///
    /// NOTE: No checking goes on to ensure this is a real public key. Only use it if
    /// you are certain that the array actually is a pubkey. GIGO!
    fn from_slice(data: &[u8]) -> Self;

    /// Return a `Vec<u8>` filled with raw data.
    fn to_raw_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }

    /// Return a slice filled with raw data.
    fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

/// An error with the interpretation of a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStringError {
    /// The overall format was invalid (e.g. the seed phrase contained symbols).
    InvalidFormat,
    /// The seed phrase provided is not a valid BIP39 phrase.
    InvalidPhrase,
    /// The supplied password was invalid.
    InvalidPassword,
    /// The seed is invalid (bad content).
    InvalidSeed,
    /// The seed has an invalid length.
    InvalidSeedLength,
    /// The derivation path was invalid (e.g. contains soft junctions when they are not supported).
    InvalidPath,
}

/// Trait suitable for typical cryptographic PKI key pair type.
///
/// For now it just specifies how to create a key from a phrase and derivation path.
pub trait Pair: CryptoType + Sized + Clone + Send + Sync + 'static {
    /// The type which is used to encode a public key.
    type Public: Public;

    /// The type used to (minimally) encode the data required to securely create
    /// a new key pair.
    type Seed: Default + AsRef<[u8]> + AsMut<[u8]> + Clone;

    /// The type used to represent a signature. Can be created from a key pair and a message
    /// and verified with the message and a public key.
    type Signature: AsRef<[u8]> + AsMut<[u8]> + Default;

    /// Error returned from the `derive` function.
    type DeriveError;

    /// Generate new secure (random) key pair.
    ///
    /// This is only for ephemeral keys really, since you won't have access to the secret key
    /// for storage. If you want a persistent key pair, use `generate_with_phrase` instead.
    fn generate() -> (Self, Self::Seed) {
        let mut seed = Self::Seed::default();
        OsRng.fill_bytes(seed.as_mut());
        (Self::from_seed(&seed), seed)
    }

    /// Generate new secure (random) key pair and provide the recovery phrase.
    ///
    /// You can recover the same key later with `from_phrase`.
    ///
    /// This is generally slower than `generate()`, so prefer that unless you need to persist
    /// the key from the current session.
    fn generate_with_phrase(password: Option<&str>) -> (Self, String, Self::Seed);

    /// Returns the KeyPair from the English BIP39 seed `phrase`, or `None` if it's invalid.
    fn from_phrase(
        phrase: &str,
        password: Option<&str>,
    ) -> Result<(Self, Self::Seed), SecretStringError>;

    /// Derive a child key from a series of given junctions.
    fn derive<Iter: Iterator<Item = DeriveJunction>>(
        &self,
        path: Iter,
        seed: Option<Self::Seed>,
    ) -> Result<(Self, Option<Self::Seed>), Self::DeriveError>;

    /// Generate new key pair from the provided `seed`.
    ///
    /// @WARNING: THIS WILL ONLY BE SECURE IF THE `seed` IS SECURE. If it can be guessed
    /// by an attacker then they can also derive your key.
    fn from_seed(seed: &Self::Seed) -> Self;

    /// Make a new key pair from secret seed material. The slice must be the correct size or
    /// it will return `None`.
    ///
    /// @WARNING: THIS WILL ONLY BE SECURE IF THE `seed` IS SECURE. If it can be guessed
    /// by an attacker then they can also derive your key.
    fn from_seed_slice(seed: &[u8]) -> Result<Self, SecretStringError>;

    /// Sign a message.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Verify a signature on a message. Returns true if the signature is good.
    fn verify<M: AsRef<[u8]>>(sig: &Self::Signature, message: M, pubkey: &Self::Public) -> bool;

    /// Verify a signature on a message. Returns true if the signature is good.
    fn verify_weak<P: AsRef<[u8]>, M: AsRef<[u8]>>(sig: &[u8], message: M, pubkey: P) -> bool;

    /// Get the public key.
    fn public(&self) -> Self::Public;

    /// Interprets the string `s` in order to generate a key Pair. Returns both the pair and an optional seed, in the
    /// case that the pair can be expressed as a direct derivation from a seed (some cases, such as Sr25519 derivations
    /// with path components, cannot).
    ///
    /// This takes a helper function to do the key generation from a phrase, password and
    /// junction iterator.
    ///
    /// - If `s` is a possibly `0x` prefixed 64-digit hex string, then it will be interpreted
    /// directly as a `MiniSecretKey` (aka "seed" in `subkey`).
    /// - If `s` is a valid BIP-39 key phrase of 12, 15, 18, 21 or 24 words, then the key will
    /// be derived from it. In this case:
    ///   - the phrase may be followed by one or more items delimited by `/` characters.
    ///   - the path may be followed by `///`, in which case everything after the `///` is treated
    /// as a password.
    /// - If `s` begins with a `/` character it is prefixed with the Substrate public `DEV_PHRASE` and
    /// interpreted as above.
    ///
    /// In this case they are interpreted as HDKD junctions; purely numeric items are interpreted as
    /// integers, non-numeric items as strings. Junctions prefixed with `/` are interpreted as soft
    /// junctions, and with `//` as hard junctions.
    ///
    /// There is no correspondence mapping between SURI strings and the keys they represent.
    /// Two different non-identical strings can actually lead to the same secret being derived.
    /// Notably, integer junction indices may be legally prefixed with arbitrary number of zeros.
    /// Similarly an empty password (ending the SURI with `///`) is perfectly valid and will generally
    /// be equivalent to no password at all.
    ///
    /// `None` is returned if no matches are found.
    fn from_string_with_seed(
        s: &str,
        password_override: Option<&str>,
    ) -> Result<(Self, Option<Self::Seed>), SecretStringError> {
        let re = Regex::new(r"^(?P<phrase>[\d\w ]+)?(?P<path>(//?[^/]+)*)(///(?P<password>.*))?$")
            .expect("constructed from known-good static value; qed");
        let cap = re.captures(s).ok_or(SecretStringError::InvalidFormat)?;

        let re_junction =
            Regex::new(r"/(/?[^/]+)").expect("constructed from known-good static value; qed");
        let path = re_junction
            .captures_iter(&cap["path"])
            .map(|f| DeriveJunction::from(&f[1]));

        let phrase = cap
            .name("phrase")
            .map(|r| r.as_str())
            .ok_or(SecretStringError::InvalidPhrase)?;
        let password = password_override.or_else(|| cap.name("password").map(|m| m.as_str()));

        let (root, seed) = if phrase.starts_with("0x") {
            hex::decode(&phrase[2..])
                .ok()
                .and_then(|seed_vec| {
                    let mut seed = Self::Seed::default();
                    if seed.as_ref().len() == seed_vec.len() {
                        seed.as_mut().copy_from_slice(&seed_vec);
                        Some((Self::from_seed(&seed), seed))
                    } else {
                        None
                    }
                })
                .ok_or(SecretStringError::InvalidSeed)?
        } else {
            Self::from_phrase(phrase, password).map_err(|_| SecretStringError::InvalidPhrase)?
        };
        root.derive(path, Some(seed))
            .map_err(|_| SecretStringError::InvalidPath)
    }

    /// Interprets the string `s` in order to generate a key pair.
    ///
    /// See [`from_string_with_seed`](Self::from_string_with_seed) for more extensive documentation.
    fn from_string(s: &str, password_override: Option<&str>) -> Result<Self, SecretStringError> {
        Self::from_string_with_seed(s, password_override).map(|x| x.0)
    }

    /// Return a vec filled with raw data.
    fn to_raw_vec(&self) -> Vec<u8>;
}

/// Type which has a particular kind of crypto associated with it.
pub trait CryptoType {
    /// The pair key type of this crypto.
    type Pair: Pair;
}

/// An identifier for a specific cryptographic algorithm used by a key pair
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct CryptoTypeId(pub [u8; 4]);

impl<'a> TryFrom<&'a str> for CryptoTypeId {
    type Error = ();

    fn try_from(x: &'a str) -> Result<CryptoTypeId, ()> {
        let mut r = [0u8; 4];
        r.copy_from_slice(x.as_bytes());
        Ok(CryptoTypeId(r))
    }
}

impl From<CryptoTypeId> for String {
    fn from(x: CryptoTypeId) -> String {
        match str::from_utf8(&x.0[..]) {
            Ok(id) => id.to_string(),
            Err(_) => format!("{:#?}", x.0),
        }
    }
}

/// A type alias of CryptoTypeId & a public key
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct CryptoTypePublicPair(pub CryptoTypeId, pub Vec<u8>);

impl std::fmt::Display for CryptoTypePublicPair {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let id = match str::from_utf8(&(self.0).0[..]) {
            Ok(id) => id.to_string(),
            Err(_) => format!("{:#?}", self.0),
        };
        write!(f, "{}-{}", id, HexDisplay::from(&self.1))
    }
}

/// An error type for SS58 decoding.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum PublicError {
    /// Bad alphabet.
    BadBase58,
    /// Bad length.
    BadLength,
    /// Unknown version.
    UnknownVersion,
    /// Invalid checksum.
    InvalidChecksum,
    /// Invalid format.
    InvalidFormat,
    /// Invalid derivation path.
    InvalidPath,
}

const PREFIX: &[u8] = b"SS58PRE";
fn ss58hash(data: &[u8]) -> blake2_rfc::blake2b::Blake2bResult {
    let mut context = blake2_rfc::blake2b::Blake2b::new(64);
    context.update(PREFIX);
    context.update(data);
    context.finalize()
}

/// Key that can be encoded to/from SS58.
pub trait Ss58Codec: Sized + AsMut<[u8]> + AsRef<[u8]> + Default {
    /// Some if the string is a properly encoded SS58Check address.
    fn from_ss58check(s: &str) -> Result<Self, PublicError> {
        Self::from_ss58check_with_version(s).and_then(|(r, v)| match v {
            v if !v.is_custom() => Ok(r),
            v if v == Ss58AddressFormat::default() => Ok(r),
            _ => Err(PublicError::UnknownVersion),
        })
    }
    /// Some if the string is a properly encoded SS58Check address.
    fn from_ss58check_with_version(s: &str) -> Result<(Self, Ss58AddressFormat), PublicError> {
        let mut res = Self::default();
        let len = res.as_mut().len();
        let d = s.from_base58().map_err(|_| PublicError::BadBase58)?; // failure here would be invalid encoding.
        if d.len() != len + 3 {
            // Invalid length.
            return Err(PublicError::BadLength);
        }
        let ver = d[0]
            .try_into()
            .map_err(|_: ()| PublicError::UnknownVersion)?;

        if d[len + 1..len + 3] != ss58hash(&d[0..len + 1]).as_bytes()[0..2] {
            // Invalid checksum.
            return Err(PublicError::InvalidChecksum);
        }
        res.as_mut().copy_from_slice(&d[1..len + 1]);
        Ok((res, ver))
    }
    /// Some if the string is a properly encoded SS58Check address, optionally with
    /// a derivation path following.
    fn from_string(s: &str) -> Result<Self, PublicError> {
        Self::from_string_with_version(s).and_then(|(r, v)| match v {
            v if !v.is_custom() => Ok(r),
            v if v == Ss58AddressFormat::default() => Ok(r),
            _ => Err(PublicError::UnknownVersion),
        })
    }

    /// Some if the string is a properly encoded SS58Check address, optionally with
    /// a derivation path following.
    fn from_string_with_version(s: &str) -> Result<(Self, Ss58AddressFormat), PublicError> {
        Self::from_ss58check_with_version(s)
    }

    /// Return the ss58-check string for this key.
    fn to_ss58check_with_version(&self, version: Ss58AddressFormat) -> String {
        let mut v = vec![version.into()];
        v.extend(self.as_ref());
        let r = ss58hash(&v);
        v.extend(&r.as_bytes()[0..2]);
        v.to_base58()
    }
    /// Return the ss58-check string for this key.
    fn to_ss58check(&self) -> String {
        self.to_ss58check_with_version(Ss58AddressFormat::default())
    }
}

impl<T: Sized + AsMut<[u8]> + AsRef<[u8]> + Default + Derive> Ss58Codec for T {
    fn from_string_with_version(s: &str) -> Result<(Self, Ss58AddressFormat), PublicError> {
        let re = Regex::new(r"^(?P<ss58>[\w\d ]+)?(?P<path>(//?[^/]+)*)$")
            .expect("constructed from known-good static value; qed");
        let cap = re.captures(s).ok_or(PublicError::InvalidFormat)?;
        let re_junction =
            Regex::new(r"/(/?[^/]+)").expect("constructed from known-good static value; qed");
        let (addr, v) = Self::from_ss58check_with_version(
            cap.name("ss58")
                .map(|r| r.as_str())
                .ok_or(PublicError::InvalidFormat)?,
        )?;
        if cap["path"].is_empty() {
            Ok((addr, v))
        } else {
            let path = re_junction
                .captures_iter(&cap["path"])
                .map(|f| DeriveJunction::from(&f[1]));
            addr.derive(path)
                .ok_or(PublicError::InvalidPath)
                .map(|a| (a, v))
        }
    }
}

macro_rules! ss58_address_format {
	( $( $identifier:tt => ($number:expr, $name:expr, $desc:tt) )* ) => (
		/// A known address (sub)format/network ID for SS58.
		#[derive(Copy, Clone, Debug, PartialEq, Eq)]
		pub enum Ss58AddressFormat {
			$(#[doc = $desc] $identifier),*,
			/// Use a manually provided numeric value.
			Custom(u8),
		}

		static ALL_SS58_ADDRESS_FORMATS: [Ss58AddressFormat; 0 $(+ { let _ = $number; 1})*] = [
			$(Ss58AddressFormat::$identifier),*,
		];

		impl Ss58AddressFormat {
			/// All known address formats.
			pub fn all() -> &'static [Ss58AddressFormat] {
				&ALL_SS58_ADDRESS_FORMATS
			}

			/// Whether the address is custom.
			pub fn is_custom(&self) -> bool {
				match self {
					Self::Custom(_) => true,
					_ => false,
				}
			}
		}

		impl From<Ss58AddressFormat> for u8 {
			fn from(x: Ss58AddressFormat) -> u8 {
				match x {
					$(Ss58AddressFormat::$identifier => $number),*,
					Ss58AddressFormat::Custom(n) => n,
				}
			}
		}

		impl TryFrom<u8> for Ss58AddressFormat {
			type Error = ();

			fn try_from(x: u8) -> Result<Ss58AddressFormat, ()> {
				match x {
					$($number => Ok(Ss58AddressFormat::$identifier)),*,
					_ => Err(()),
				}
			}
		}

		impl<'a> TryFrom<&'a str> for Ss58AddressFormat {
			type Error = ();

			fn try_from(x: &'a str) -> Result<Ss58AddressFormat, ()> {
				match x {
					$($name => Ok(Ss58AddressFormat::$identifier)),*,
					a => a.parse::<u8>().map(Ss58AddressFormat::Custom).map_err(|_| ()),
				}
			}
		}

		impl Default for Ss58AddressFormat {
			fn default() -> Self {
				*DEFAULT_VERSION.lock().expect("mutex lock error")
			}
		}

		impl From<Ss58AddressFormat> for String {
			fn from(x: Ss58AddressFormat) -> String {
				match x {
					$(Ss58AddressFormat::$identifier => $name.into()),*,
					Ss58AddressFormat::Custom(x) => x.to_string(),
				}
			}
		}
	)
}

lazy_static::lazy_static! {
    static ref DEFAULT_VERSION: Mutex<Ss58AddressFormat>
        = Mutex::new(Ss58AddressFormat::Transparent);
}

ss58_address_format!(
    Transparent  =>
        (0, "transparent", "transparent payment address.")
    Shielded  =>
        (1, "shielded", "shielded payment address.")
);
