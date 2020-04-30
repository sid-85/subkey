use bip39::{Language, Mnemonic, MnemonicType};
use clap::{App, ArgMatches, SubCommand};
use std::fmt;
use std::fs;
use std::io::stdin;
use std::io::Read;
use std::str::FromStr;
use std::convert::{TryInto};
use std::path::PathBuf;

use subkey::crypto::crypto::*;
use subkey::crypto::crypto::{Ss58AddressFormat, Ss58Codec};
use subkey::Crypto;
use subkey::Ed25519;
use subkey::Sr25519;
use subkey::Ecdsa;
use subkey::SignatureOf;
use subkey::PublicOf;
use subkey::format_signature;


fn get_usage() -> String {
	let address_formats = "";// Ss58AddressFormat::all().iter().cloned().map(String::from).join("/");
	let default_address_format = String::from(Ss58AddressFormat::default());
	format!("
		-e, --ed25519 'Use Ed25519/BIP39 cryptography'
		-k, --secp256k1 'Use SECP256k1/ECDSA/BIP39 cryptography'
		-s, --sr25519 'Use Schnorr/Ristretto x25519/BIP39 cryptography'
		[format] -f, --format <format> 'Specify a address format. One of {}. Default is {}'
		[password] -p, --password <password> 'The password for the key'
		--password-interactive 'You will be prompted for the password for the key.'
		[output] -o, --output <output> 'Specify an output format. One of text, json. Default is text.'
	", address_formats, default_address_format)
}

fn get_app<'a, 'b>(usage: &'a str) -> App<'a, 'b> {
	App::new("crypto")
		.author("xuke tech team <admin@xuke.io>")
		.about("Utility for generating and restoring with crypto keys")
		.version(env!("CARGO_PKG_VERSION"))
		.args_from_usage(usage)
		.subcommands(vec![
			SubCommand::with_name("generate")
				.about("Generate a random account")
				.args_from_usage("[words] -w, --words <words> \
						'The number of words in the phrase to generate. One of 12 \
						(default), 15, 18, 21 and 24.'
				"),
			SubCommand::with_name("inspect")
				.about("Gets a public key and a SS58 address from the provided Secret URI")
				.args_from_usage("[uri] 'A Key URI to be inspected. May be a secret seed, \
						secret URI (with derivation paths and password), SS58 or public URI. \
						If the value is a file, the file content is used as URI. \
						If not given, you will be prompted for the URI.'
				"),
			SubCommand::with_name("sign")
				.about("Sign a message, provided on STDIN, with a given (secret) key")
				.args_from_usage("
					-h, --hex 'The message on STDIN is hex-encoded data'
					<suri> 'The secret key URI. \
						If the value is a file, the file content is used as URI. \
						If not given, you will be prompted for the URI.'
				"),
			SubCommand::with_name("vanity")
				.about("Generate a seed that provides a vanity address")
				.args_from_usage("
					-n, --number <number> 'Number of keys to generate'
					<pattern> 'Desired pattern'
				")
		])
}

fn main() -> Result<(), Error> {
	let usage = get_usage();
	let matches = get_app(&usage).get_matches();

	if matches.is_present("ed25519") {
		return execute::<Ed25519>(matches);
	}
	if matches.is_present("secp256k1") {
		return execute::<Ecdsa>(matches)
	}
	return execute::<Sr25519>(matches)
}

/// Get `URI` from CLI or prompt the user.
///
/// `URI` is extracted from `matches` by using `match_name`.
///
/// If the `URI` given as CLI argument is a file, the file content is taken as `URI`.
/// If no `URI` is given to the CLI, the user is prompted for it.
fn get_uri(match_name: &str, matches: &ArgMatches) -> Result<String, Error> {
	let uri = if let Some(uri) = matches.value_of(match_name) {
		let file = PathBuf::from(uri);
		if file.is_file() {
			fs::read_to_string(uri)?
				.trim_end()
				.into()
		} else {
			uri.into()
		}
	} else {
		rpassword::read_password_from_tty(Some("URI: "))?
	};

	Ok(uri)
}

#[derive(derive_more::Display, derive_more::From)]
enum Error {
	Static(&'static str),
	Io(std::io::Error),
	Formatted(String),
}

impl fmt::Debug for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

fn static_err(msg: &'static str) -> Result<(), Error> {
	Err(Error::Static(msg))
}

fn execute<C: Crypto>(matches: ArgMatches) -> Result<(), Error>
{
	let password_interactive = matches.is_present("password-interactive");
	let password = matches.value_of("password");

	let password = if password.is_some() && password_interactive {
		return static_err("`--password` given and `--password-interactive` selected!");
	} else if password_interactive {
		Some(
			rpassword::read_password_from_tty(Some("Key password: "))?
		)
	} else {
		password.map(Into::into)
	};
	let password = password.as_ref().map(String::as_str);

	let maybe_address_format: Option<Ss58AddressFormat> = match matches.value_of("format").map(|network| {
		network
			.try_into()
			.map_err(|_| Error::Static("Invalid address format name. See --help for available address formats."))
	}) {
		Some(Err(e)) => return Err(e),
		Some(Ok(v)) => Some(v),
		None => None,
	 };

	match matches.subcommand() {
		("generate", Some(matches)) => {
			let mnemonic = generate_mnemonic(matches)?;
			C::print_from_uri(mnemonic.phrase(), password, maybe_address_format);
		}
		("inspect", Some(matches)) => {
			C::print_from_uri(&get_uri("uri", &matches)?, password, maybe_address_format);
		}
		("sign", Some(matches)) => {
			let suri = get_uri("suri", &matches)?;
			let should_decode = matches.is_present("hex");

			let message = read_message_from_stdin(should_decode)?;
			let signature = do_sign::<C>(&suri, message, password)?;
			println!("{}", signature);
		}
		("verify", Some(matches)) => {
			let uri = get_uri("uri", &matches)?;
			let should_decode = matches.is_present("hex");

			let message = read_message_from_stdin(should_decode)?;
			let is_valid_signature = do_verify::<C>(matches, &uri, message)?;
			if is_valid_signature {
				println!("Signature verifies correctly.");
			} else {
				return static_err("Signature invalid.");
			}
		}
		_ => print_usage(&matches),
	}

	Ok(())
}

/// Creates a new randomly generated mnemonic phrase.
fn generate_mnemonic(matches: &ArgMatches) -> Result<Mnemonic, Error> {
	let words = match matches.value_of("words") {
		Some(words) => {
			let num = usize::from_str(words).map_err(|_| Error::Static("Invalid number given for --words"))?;
			MnemonicType::for_word_count(num)
				.map_err(|_| Error::Static("Invalid number of words given for phrase: must be 12/15/18/21/24"))?
		},
		None => MnemonicType::Words12,
	};
	Ok(Mnemonic::new(words, Language::English))
}

fn do_sign<C: Crypto>(suri: &str, message: Vec<u8>, password: Option<&str>) -> Result<String, Error>
{
	let pair = read_pair::<C>(Some(suri), password)?;
	let signature = pair.sign(&message);
	Ok(format_signature::<C>(&signature))
}

fn do_verify<C: Crypto>(matches: &ArgMatches, uri: &str, message: Vec<u8>) -> Result<bool, Error>
{

	let signature = read_signature::<C>(matches)?;
	let pubkey = read_public_key::<C>(Some(uri));
	Ok(<<C as Crypto>::Pair as Pair>::verify(&signature, &message, &pubkey))
}

fn decode_hex<T: AsRef<[u8]>>(message: T) -> Result<Vec<u8>, Error> {
	hex::decode(message).map_err(|e| Error::Formatted(format!("Invalid hex ({})", e)))
}

fn read_message_from_stdin(should_decode: bool) -> Result<Vec<u8>, Error> {
	let mut message = vec![];
	stdin()
		.lock()
		.read_to_end(&mut message)?;
	if should_decode {
		message = decode_hex(&message)?;
	}
	Ok(message)
}

fn read_signature<C: Crypto>(matches: &ArgMatches) -> Result<SignatureOf<C>, Error>
{
	let sig_data = matches
		.value_of("sig")
		.expect("signature parameter is required; thus it can't be None; qed");
	let mut signature = <<C as Crypto>::Pair as Pair>::Signature::default();
	let sig_data = decode_hex(sig_data)?;
	if sig_data.len() != signature.as_ref().len() {
		return Err(Error::Formatted(format!(
			"signature has an invalid length. read {} bytes, expected {} bytes",
			sig_data.len(),
			signature.as_ref().len(),
		)));
	}
	signature.as_mut().copy_from_slice(&sig_data);
	Ok(signature)
}

fn read_public_key<C: Crypto>(matched_uri: Option<&str>) -> PublicOf<C>
{
	let uri = matched_uri.expect("parameter is required; thus it can't be None; qed");
	let uri = if uri.starts_with("0x") {
		&uri[2..]
	} else {
		uri
	};
	if let Ok(pubkey_vec) = hex::decode(uri) {
		<C as Crypto>::Public::from_slice(pubkey_vec.as_slice())
	} else {
		<C as Crypto>::Public::from_string(uri)
			.ok()
			.expect("Invalid URI; expecting either a secret URI or a public URI.")
	}
}

fn read_pair<C: Crypto>(
	matched_suri: Option<&str>,
	password: Option<&str>,
) -> Result<<C as Crypto>::Pair, Error> 
{
	let suri = matched_suri.ok_or(Error::Static("parameter is required; thus it can't be None; qed"))?;
	Ok(C::pair_from_suri(suri, password))
}

fn print_usage(matches: &ArgMatches) {
	println!("{}", matches.usage());
}
