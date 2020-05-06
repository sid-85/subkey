use clap::ArgMatches;

pub fn run_keys(args: &ArgMatches) {
    let _url = args.value_of("url");
    match args.subcommand() {
        ("gen", Some(args)) => {
            add_new_address(args);
        }
        ("import", Some(args)) => {
            import_new_address(args);
        }
        ("export", Some(args)) => {
            export_address(args);
        }
        ("sign", Some(args)) => {
            sign_message(args);
        }
        ("verify", Some(args)) => {
            verify_message(args);
        }
        _ => println!("{}", args.usage()),
    }
}

fn add_new_address(_args: &ArgMatches) {}

fn import_new_address(_args: &ArgMatches) {}
fn export_address(_args: &ArgMatches) {}
fn sign_message(_args: &ArgMatches) {}
fn verify_message(_args: &ArgMatches) {}
