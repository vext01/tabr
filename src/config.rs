use std::fs::File;
use std::path::PathBuf;
use std::io::Read;
use toml;
use std::process::Command;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub static CONFIG_FILENAME: &'static str = "config.toml";

#[derive(Debug)]
pub struct NoConfig(PathBuf);  // Expected a config file at the location addressed by the PathBuf.

impl Error for NoConfig {
    fn description(&self) -> &str {
        "No config file present"
    }
}

impl Display for NoConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "No config file present at '{}'", self.0.display())
    }
}

impl NoConfig {
    pub fn path(&self) -> &PathBuf {
        &self.0
    }
}

/// An in-memory representation of the user's config file.
#[derive(Debug, Deserialize)]
pub struct Config {
    encrypt_to: Vec<String>,        // Patterns used to select GnuPG recipients.
    menu_program: Option<PathBuf>,  // Path to a dmenu compatible program to use for the menu.
    clipboard_timeout: Option<u32>, // The number of seconds to wait before clearing the clipboard.
    menu_args: Option<Vec<String>>, // Arguments to pass to the menu program, if any.
    notify_program: Option<PathBuf>,// Path to a notify-send compatible program for sending notifications.
}

impl Config {
    pub fn new(state_dir: &PathBuf) -> Result<Self, Box<Error>> {
        // Read in the user's config file.
        let mut config_path = state_dir.clone();
        config_path.push(CONFIG_FILENAME);
        let mut conf: Self = if config_path.exists() {
            let mut fh = File::open(config_path)?;
            let mut config_text = String::new();
            fh.read_to_string(&mut config_text)?;
            toml::from_str(&config_text)?
        } else {
            return Err(Box::new(NoConfig(config_path)));
        };

        // Populate absent optional fields where necessary.
        if conf.clipboard_timeout.is_none() {
            conf.clipboard_timeout = Some(5);
        }
        if conf.menu_program.is_none() {
            conf.menu_program = find_executable("dmenu")?;
        }
        if conf.menu_args.is_none() {
            conf.menu_args = Some(Vec::new());
        }
        if conf.notify_program.is_none() {
            conf.notify_program = find_executable("notify-send")?;
        }

        info!("config: {:?}", conf);
        Ok(conf)
    }

    pub fn encrypt_to(&self) -> &Vec<String> {
        &self.encrypt_to
    }

    pub fn menu_program(&self) -> &Option<PathBuf> {
        &self.menu_program
    }

    pub fn clipboard_timeout(&self) -> u32 {
        self.clipboard_timeout.unwrap()
    }

    pub fn menu_args(&self) -> &Vec<String> {
        &self.menu_args.as_ref().unwrap()
    }

    pub fn notify_program(&self) -> &Option<PathBuf> {
        &self.notify_program
    }
}

pub fn find_executable(name: &str) -> Result<Option<PathBuf>, Box<Error>> {
    let output = Command::new("which")
                         .arg(name)
                         .output()?;

    let res = match output.status.success() {
        true => Some(PathBuf::from(String::from_utf8(output.stdout)?.trim())),
        false => None,
    };

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::{PathBuf, find_executable};

    #[test]
    fn test_find_executable1() {
        let expect = Some(PathBuf::from(String::from("/bin/sh")));
        assert_eq!(find_executable("sh").unwrap(), expect);
    }

    #[test]
    fn test_find_executable2() {
        assert_eq!(find_executable("wibbleywobbley").unwrap(), None);
    }
}

