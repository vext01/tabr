extern crate tabr;
extern crate ttyaskpass;
extern crate clap;
#[macro_use]
extern crate log;
extern crate env_logger;

use tabr::{Tabr, ClearPassword, NoConfig, PasswordEdit};
use ttyaskpass::askpass;

use std::path::PathBuf;
use std::env;
use std::error::Error;
use clap::{Arg, App, SubCommand};
use std::process::exit;

fn print_error(msg: &str) -> ! {
    eprintln!("Error: {}", msg);
    exit(1);
}

/// Prints first-time use information on how to build a config file.
fn advise_config(path: &PathBuf) -> ! {
    let rule = "-".repeat(72);

    println!("{}", rule);
    println!("No config file found.\n");
    println!("To get started put the following into '{}'\n", path.display());
    println!("```");
    println!("encrypt_to = [\"your-gnupg-key-hash\"]");
    println!("```\n");
    println!("If you don't yet have a GnuPG key, GitHub hosts a guide here:");
    println!("https://help.github.com/articles/generating-a-new-gpg-key/\n");
    println!("Please consider using subkeys with a stripped master key and\n\
             a hardware token such as YubiKey.");

    println!("{}", rule);
    exit(1);

}

fn main() {
    env_logger::init().expect("failed to init logger");
    info!("starting up");

    // Figure out where the state directory is.
    let state_dir: PathBuf = {
        match env::var("TABR_DIR") {
            Ok(path) => PathBuf::from(path),
            _ => {
                let mut path = match env::home_dir() {
                    None => print_error("Can't determine home directory"),
                    Some(h) => h,
                };
                path.push(".tabr");
                path
            }
        }
    };
    info!("state dir is '{}'", state_dir.display());

    let mut tabr = match Tabr::new(state_dir, None) {
        Ok(x) => x,
        Err(e) => {
            match e.is::<NoConfig>() {
                true => {
                    let no_conf_err = e.downcast::<NoConfig>().unwrap();
                    advise_config(no_conf_err.path());
                }
                _ => print_error(&format!("Failed to initialise: {}", e)),
            }
        }
    };

    let app = App::new("tabr")
                  .version("0.1.0")
                  .author("Edd Barrett <vext01@gmail.com>")
                  .about("Simple password store");

    let app = app.subcommand(SubCommand::with_name("ls")
                                        .about("List passwords in the store")
                                        .arg(Arg::with_name("verbose")
                                                 .short("-v")
                                                 .long("--verbose")))
                 .subcommand(SubCommand::with_name("add")
                                        .arg(Arg::with_name("pwid")
                                                 .index(1)
                                                 .required(true)
                                                 .takes_value(true))
                                        .arg(Arg::with_name("username")
                                                 .short("-u")
                                                 .long("--username")
                                                 .takes_value(true))
                                        .arg(Arg::with_name("email")
                                                 .short("-e")
                                                 .long("--email")
                                                 .takes_value(true))
                                        .arg(Arg::with_name("comment")
                                                 .short("-c")
                                                 .long("--comment")
                                                 .takes_value(true))
                                        .about("Add a password to the store"))
                 .subcommand(SubCommand::with_name("menu")
                                        .about("Choose a password from a menu and load the clipboard"))
                 .subcommand(SubCommand::with_name("clip")
                                        .arg(Arg::with_name("pwid")
                                                 .index(1)
                                                 .required(true)
                                                 .takes_value(true))
                                        .about("Temporarily load a password into the clipboard"))
                 .subcommand(SubCommand::with_name("edit")
                                        .arg(Arg::with_name("username")
                                                 .short("-u")
                                                 .long("--username")
                                                 .takes_value(true)
                                                 .help("Set the username (pass \"\" to \
                                                        remove the existing username)"))
                                        .arg(Arg::with_name("email")
                                                 .short("-e")
                                                 .long("--email")
                                                 .takes_value(true)
                                                 .help("Set the email address (pass \"\" \
                                                        to remove the existing address)"))
                                        .arg(Arg::with_name("comment")
                                                 .short("-c")
                                                 .long("--comment")
                                                 .takes_value(true)
                                                 .help("Set the comment address (pass \"\" \
                                                        to remove the existing comment)"))
                                        .arg(Arg::with_name("--password")
                                                 .short("-p")
                                                 .long("--password")
                                                 .help("Request a password reset"))
                                        .arg(Arg::with_name("pwid")
                                                 .index(1)
                                                 .required(true)
                                                 .takes_value(true)
                                                 .help("The ID of the password to edit"))
                                        .about("Edit the contents of an existing password \
                                                entry"))
                 .subcommand(SubCommand::with_name("stdout")
                                        .arg(Arg::with_name("pwid")
                                                 .index(1)
                                                 .required(true)
                                                 .takes_value(true))
                                        .about("Prints a password in the clear to stdout"));

    fn match_to_arg(m: Option<&str>) -> Option<String> {
        m.map(|s| String::from(s))
    }

    fn read_cleartext() -> String {
        let clear_text_arr: Vec<u8> = askpass("password: ", '*').unwrap();
        String::from_utf8(clear_text_arr)
               .unwrap_or_else(|_|print_error("failed to read in cleartext"))
    }

    let matches = app.get_matches();
    let res: Result<(), Box<Error>> = match matches.subcommand_name() {
        Some("ls") => {
            let matches = matches.subcommand_matches("ls").unwrap();
            tabr.list_passwords(matches.is_present("verbose"))
        },
        Some("add") => {
            let matches = matches.subcommand_matches("add").unwrap();
            let pwid = matches.value_of("pwid").unwrap();
            let username = match_to_arg(matches.value_of("username"));
            let email = match_to_arg(matches.value_of("email"));
            let comment = match_to_arg(matches.value_of("comment"));

            // Read in the password as late as possible.
            let clear_text = read_cleartext();

            let mut pw = ClearPassword::new(username, email, comment, clear_text);
            tabr.add_password(&pwid, pw)
        },
        Some("clip") => {
            let matches = matches.subcommand_matches("clip").unwrap();
            tabr.clip(matches.value_of("pwid").unwrap())
        },
        Some("edit") => {
            let matches = matches.subcommand_matches("edit").unwrap();

            let pwid = matches.value_of("pwid").unwrap();

            let username = match_to_arg(matches.value_of("username"));
            let email = match_to_arg(matches.value_of("email"));
            let comment = match_to_arg(matches.value_of("comment"));

            let clear_text = if matches.value_of("password").is_some() {
                // Read in the password as late as possible.
                Some(read_cleartext())
            } else {
                None
            };

            let mut pwe = PasswordEdit::new(username, email, comment, clear_text);
            tabr.edit_password(&pwid, pwe)
        },
        Some("stdout") => {
            let matches = matches.subcommand_matches("stdout").unwrap();
            tabr.stdout(matches.value_of("pwid").unwrap())
        },
        Some("menu") => tabr.menu(),
        _ => {
            println!("{}", matches.usage());
            Ok(())
        },
    };

    // If something went wrong, report what.
    match res {
        Err(e) => print_error(&e.to_string()),
        _ => (),
    }
}
