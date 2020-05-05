// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use super::{
    password::Password, Aes128Ctr, Bytes, Cipher, CipherSer, CipherSerParams, Kdf, KdfSer,
    KdfSerParams, Pbkdf2, Prf, Random, H128, H256,
};
use parity_crypto as crypto;
use parity_crypto::Keccak256;
use serde::de::{Error, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;
use smallvec::SmallVec;
use std::{fmt, num::NonZeroU32, str};

pub type CipherText = Bytes;

#[derive(Debug, PartialEq)]
pub struct Crypto {
    pub cipher: Cipher,
    pub ciphertext: CipherText,
    pub kdf: Kdf,
    pub mac: H256,
}

impl str::FromStr for Crypto {
    type Err = serde_json::error::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl From<Crypto> for String {
    fn from(c: Crypto) -> Self {
        serde_json::to_string(&c)
            .expect("serialization cannot fail, cause all crypto keys are strings")
    }
}

enum CryptoField {
    Cipher,
    CipherParams,
    CipherText,
    Kdf,
    KdfParams,
    Mac,
    Version,
}

impl<'a> Deserialize<'a> for CryptoField {
    fn deserialize<D>(deserializer: D) -> Result<CryptoField, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_any(CryptoFieldVisitor)
    }
}

struct CryptoFieldVisitor;

impl<'a> Visitor<'a> for CryptoFieldVisitor {
    type Value = CryptoField;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a valid crypto struct description")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match value {
            "cipher" => Ok(CryptoField::Cipher),
            "cipherparams" => Ok(CryptoField::CipherParams),
            "ciphertext" => Ok(CryptoField::CipherText),
            "kdf" => Ok(CryptoField::Kdf),
            "kdfparams" => Ok(CryptoField::KdfParams),
            "mac" => Ok(CryptoField::Mac),
            "version" => Ok(CryptoField::Version),
            _ => Err(Error::custom(format!("Unknown field: '{}'", value))),
        }
    }
}

impl<'a> Deserialize<'a> for Crypto {
    fn deserialize<D>(deserializer: D) -> Result<Crypto, D::Error>
    where
        D: Deserializer<'a>,
    {
        static FIELDS: &'static [&'static str] = &["id", "version", "crypto", "Crypto", "address"];
        deserializer.deserialize_struct("Crypto", FIELDS, CryptoVisitor)
    }
}

struct CryptoVisitor;

impl<'a> Visitor<'a> for CryptoVisitor {
    type Value = Crypto;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a valid vault crypto object")
    }

    fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
    where
        V: MapAccess<'a>,
    {
        let mut cipher = None;
        let mut cipherparams = None;
        let mut ciphertext = None;
        let mut kdf = None;
        let mut kdfparams = None;
        let mut mac = None;

        loop {
            match visitor.next_key()? {
                Some(CryptoField::Cipher) => {
                    cipher = Some(visitor.next_value()?);
                }
                Some(CryptoField::CipherParams) => {
                    cipherparams = Some(visitor.next_value()?);
                }
                Some(CryptoField::CipherText) => {
                    ciphertext = Some(visitor.next_value()?);
                }
                Some(CryptoField::Kdf) => {
                    kdf = Some(visitor.next_value()?);
                }
                Some(CryptoField::KdfParams) => {
                    kdfparams = Some(visitor.next_value()?);
                }
                Some(CryptoField::Mac) => {
                    mac = Some(visitor.next_value()?);
                }
                // skip not required version field (it appears in pyethereum generated keystores)
                Some(CryptoField::Version) => visitor.next_value().unwrap_or(()),
                None => {
                    break;
                }
            }
        }

        let cipher = match (cipher, cipherparams) {
            (Some(CipherSer::Aes128Ctr), Some(CipherSerParams::Aes128Ctr(params))) => {
                Cipher::Aes128Ctr(params)
            }
            (None, _) => return Err(V::Error::missing_field("cipher")),
            (Some(_), None) => return Err(V::Error::missing_field("cipherparams")),
        };

        let ciphertext = match ciphertext {
            Some(ciphertext) => ciphertext,
            None => return Err(V::Error::missing_field("ciphertext")),
        };

        let kdf = match (kdf, kdfparams) {
            (Some(KdfSer::Pbkdf2), Some(KdfSerParams::Pbkdf2(params))) => Kdf::Pbkdf2(params),
            (Some(KdfSer::Scrypt), Some(KdfSerParams::Scrypt(params))) => Kdf::Scrypt(params),
            (Some(_), Some(_)) => return Err(V::Error::custom("Invalid cipherparams")),
            (None, _) => return Err(V::Error::missing_field("kdf")),
            (Some(_), None) => return Err(V::Error::missing_field("kdfparams")),
        };

        let mac = match mac {
            Some(mac) => mac,
            None => return Err(V::Error::missing_field("mac")),
        };

        let result = Crypto {
            cipher: cipher,
            ciphertext: ciphertext,
            kdf: kdf,
            mac: mac,
        };

        Ok(result)
    }
}

impl Serialize for Crypto {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut crypto = serializer.serialize_struct("Crypto", 6)?;
        match self.cipher {
            Cipher::Aes128Ctr(ref params) => {
                crypto.serialize_field("cipher", &CipherSer::Aes128Ctr)?;
                crypto.serialize_field("cipherparams", params)?;
            }
        }
        crypto.serialize_field("ciphertext", &self.ciphertext)?;
        match self.kdf {
            Kdf::Pbkdf2(ref params) => {
                crypto.serialize_field("kdf", &KdfSer::Pbkdf2)?;
                crypto.serialize_field("kdfparams", params)?;
            }
            Kdf::Scrypt(ref params) => {
                crypto.serialize_field("kdf", &KdfSer::Scrypt)?;
                crypto.serialize_field("kdfparams", params)?;
            }
        }

        crypto.serialize_field("mac", &self.mac)?;
        crypto.end()
    }
}

lazy_static! {
    static ref KEY_ITERATIONS: NonZeroU32 =
        NonZeroU32::new(crypto::KEY_ITERATIONS as u32).expect("KEY_ITERATIONS > 0; qed");
}

impl Crypto {
    /// Encrypt custom plain data
    pub fn encrypt(plain: &[u8], password: &Password) -> Result<Self, super::Error> {
        let iterations = *KEY_ITERATIONS;
        let salt: [u8; 32] = Random::random();
        let iv: [u8; 16] = Random::random();

        // two parts of derived key
        // DK = [ DK[0..15] DK[16..31] ] = [derived_left_bits, derived_right_bits]
        let (derived_left_bits, derived_right_bits) =
            crypto::derive_key_iterations(password.as_bytes(), &salt, iterations);

        // preallocated (on-stack in case of `Secret`) buffer to hold cipher
        // length = length(plain) as we are using CTR-approach
        let plain_len = plain.len();
        let mut ciphertext: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; plain_len]);

        // aes-128-ctr with initial vector of iv
        crypto::aes::encrypt_128_ctr(&derived_left_bits, &iv, plain, &mut *ciphertext)
            .map_err(|_| super::Error::UnsupportedCipher)?;

        // KECCAK(DK[16..31] ++ <ciphertext>), where DK[16..31] - derived_right_bits
        let mac = crypto::derive_mac(&derived_right_bits, &*ciphertext).keccak256();

        Ok(Crypto {
            cipher: Cipher::Aes128Ctr(Aes128Ctr { iv: H128::from(iv) }),
            ciphertext: Bytes::from(ciphertext.into_vec()),
            kdf: Kdf::Pbkdf2(Pbkdf2 {
                dklen: crypto::KEY_LENGTH as u32,
                salt: Bytes::from(salt.to_vec()),
                c: iterations,
                prf: Prf::HmacSha256,
            }),
            mac: H256::from(mac),
        })
    }

    /// Try to decrypt and return result as is
    pub fn decrypt(&self, password: &Password) -> Result<Vec<u8>, super::Error> {
        let expected_len = self.ciphertext.len();

        let (derived_left_bits, derived_right_bits) = match self.kdf {
            Kdf::Pbkdf2(ref params) => {
                crypto::derive_key_iterations(password.as_bytes(), &params.salt, params.c)
            }
            Kdf::Scrypt(ref params) => crypto::scrypt::derive_key(
                password.as_bytes(),
                &params.salt,
                params.n,
                params.p,
                params.r,
            )
            .map_err(|_| super::Error::InvalidCiphertext)?,
        };

        let mac = crypto::derive_mac(&derived_right_bits, &self.ciphertext).keccak256();

        if !crypto::is_equal(&mac, &self.mac) {
            return Err(super::Error::InvalidCiphertext);
        }

        let mut plain: SmallVec<[u8; 32]> = SmallVec::from_vec(vec![0; expected_len]);

        match self.cipher {
            Cipher::Aes128Ctr(ref params) => {
                // checker by callers
                debug_assert!(expected_len >= self.ciphertext.len());

                let from = expected_len - self.ciphertext.len();
                crypto::aes::decrypt_128_ctr(
                    &derived_left_bits,
                    &params.iv,
                    &self.ciphertext,
                    &mut plain[from..],
                )
                .map_err(|_| super::Error::InvalidCiphertext)?;
                Ok(plain.into_iter().collect())
            }
        }
    }
}
