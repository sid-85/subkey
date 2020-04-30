
use std::fmt;
use std::io::{Read, Write};
use serde::{Serialize, Deserialize, Deserializer};
use serde::de::{Error, Visitor, MapAccess, DeserializeOwned};
use serde_json;
use super::json::{Uuid, Version, Crypto};

#[derive(Debug, PartialEq, Serialize)]
pub struct KeyFile {
	pub id: Uuid,
	pub version: Version,
    pub name: String,
	pub address: String,
    pub ctype: String, 
    pub crypto: Crypto,
    pub efvk: Option<Crypto>,
	pub meta: Option<String>,
}

enum KeyFileField {
	Id,
    Version,
    Name,
    Address,
    Type,
    Crypto,
    Efvk,
	Meta,
}

impl<'a> Deserialize<'a> for KeyFileField {
	fn deserialize<D>(deserializer: D) -> Result<KeyFileField, D::Error>
		where D: Deserializer<'a>
	{
		deserializer.deserialize_any(KeyFileFieldVisitor)
	}
}

struct KeyFileFieldVisitor;

impl<'a> Visitor<'a> for KeyFileFieldVisitor {
	type Value = KeyFileField;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		write!(formatter, "a valid key file field")
	}

	fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
		where E: Error
	{
		match value {
			"id" => Ok(KeyFileField::Id),
			"version" => Ok(KeyFileField::Version),
            "name" => Ok(KeyFileField::Name),
            "address" => Ok(KeyFileField::Address),
            "type" => Ok(KeyFileField::Type),
            "crypto" => Ok(KeyFileField::Crypto),
            "efvk" => Ok(KeyFileField::Efvk),
			"meta" => Ok(KeyFileField::Meta),
			_ => Err(Error::custom(format!("Unknown field: '{}'", value))),
		}
	}
}

impl<'a> Deserialize<'a> for KeyFile {
	fn deserialize<D>(deserializer: D) -> Result<KeyFile, D::Error>
		where D: Deserializer<'a>
	{
		static FIELDS: &'static [&'static str] = &["id", "version", "name", "address", "type", "crypto", "efvk"];
		deserializer.deserialize_struct("KeyFile", FIELDS, KeyFileVisitor)
	}
}

fn none_if_empty<'a, T>(v: Option<serde_json::Value>) -> Option<T> where
	T: DeserializeOwned
{
	v.and_then(|v| if v.is_null() {
		None
	} else {
		serde_json::from_value(v).ok()
	})

}

struct KeyFileVisitor;
impl<'a> Visitor<'a> for KeyFileVisitor {
	type Value = KeyFile;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		write!(formatter, "a valid key object")
	}

	fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
		where V: MapAccess<'a>
	{
		let mut id = None;
		let mut version = None;
        let mut name = None;
        let mut address = None;
        let mut ctype = None;
        let mut crypto = None;
        let mut efvk = None;
		let mut meta = None;

		loop {
			match visitor.next_key()? {
				Some(KeyFileField::Id) => { id = Some(visitor.next_value()?); }
				Some(KeyFileField::Version) => { version = Some(visitor.next_value()?); }
                Some(KeyFileField::Crypto) => { crypto = Some(visitor.next_value()?); }
                Some(KeyFileField::Type) => { ctype = Some(visitor.next_value()?); }
                Some(KeyFileField::Address) => { address = Some(visitor.next_value()?); }
                Some(KeyFileField::Efvk) => {efvk = none_if_empty(visitor.next_value().ok())}
				Some(KeyFileField::Name) => { name = Some(visitor.next_value()?); }
                Some(KeyFileField::Meta) => { meta = none_if_empty(visitor.next_value().ok()) }
				None => { break; }
			}
		}

		let id = match id {
			Some(id) => id,
			None => return Err(V::Error::missing_field("id")),
		};

		let version = match version {
			Some(version) => version,
			None => return Err(V::Error::missing_field("version")),
        };
        
        let ctype = match ctype {
			Some(ctype) => ctype,
			None => return Err(V::Error::missing_field("type")),
		};

		let crypto = match crypto {
			Some(crypto) => crypto,
			None => return Err(V::Error::missing_field("crypto")),
        };
        
        let address = match address {
			Some(address) => address,
			None => return Err(V::Error::missing_field("address")),
        };
        
        let name = match name {
			Some(name) => name,
			None => return Err(V::Error::missing_field("name")),
		};

		let result = KeyFile {
			id: id,
			version: version,
            crypto: crypto,
            efvk: efvk,
            ctype: ctype,
			address: address,
			name: name,
			meta: meta,
		};

		Ok(result)
	}
}

impl KeyFile {
	pub fn load<R>(reader: R) -> Result<Self, serde_json::Error> where R: Read {
		serde_json::from_reader(reader)
	}

	pub fn write<W>(&self, writer: &mut W) -> Result<(), serde_json::Error> where W: Write {
		serde_json::to_writer(writer, self)
	}
}
