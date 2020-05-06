#[macro_use]
extern crate clap;
use clap::App;
use subkey::cli;
fn main() {
    let yaml = load_yaml!("cli.yaml");
    let args = App::from_yaml(yaml).get_matches();
    cli::run_keys(&args);
}
