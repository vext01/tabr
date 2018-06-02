#[macro_use] extern crate log;
extern crate env_logger;
#[macro_use]
extern crate serde_derive;

extern crate toml;
extern crate gpgme;
extern crate walkdir;
extern crate clipboard;
#[cfg(test)]
extern crate tempfile;

mod config;
mod password;
mod gpg;

pub use password::ClearPassword;

use clipboard::ClipboardProvider;
use clipboard::x11_clipboard::{X11ClipboardContext, Primary, Clipboard};
use config::Config;
use gpg::GPG;
use password::EncryptedPassword;
use std::fs::{DirBuilder, metadata};
use std::io;
use std::io::{Read, Write, stdout};
use std::os::unix::fs::DirBuilderExt;
use std::path::{PathBuf, Path};
use std::process::{Command, Stdio};
use std::{thread, time};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use walkdir::WalkDir;
pub use config::NoConfig;

static PASSWORDS_DIR_NAME: &'static str = "passwords";
pub static PROTECTED_MODE: u32 = 0o700;

// Error type used for custom error strings.
#[derive(Debug)]
struct CustomErrorMessage(String);

impl Error for CustomErrorMessage {
    fn description(&self) -> &str {
        "A custom error message"
    }
}

impl Display for CustomErrorMessage {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CustomErrorMessage {
    fn boxed(msg: String) -> Box<Self> {
        Box::new(CustomErrorMessage(msg))
    }
}

/// The "god struct".
pub struct Tabr {
    config: Config,
    state_dir: PathBuf,
    gpg: GPG,
}

impl Tabr {
    pub fn new(state_dir: PathBuf, gnupg_home: Option<PathBuf>) -> Result<Self, Box<Error>> {
        // Scaffold directories if necessary.
        let passwords_dir = Self::_passwords_dir(&state_dir);
        if !passwords_dir.exists() {
            info!("Creating: {:?}", passwords_dir);
            DirBuilder::new()
                       .recursive(true)
                       .mode(PROTECTED_MODE)
                       .create(passwords_dir.as_path())?;

        } else {
            Self::check_secure(passwords_dir.as_path());
        }

        Ok(Self {
            config: Config::new(&state_dir)?,
            state_dir: state_dir,
            gpg: GPG::new(gnupg_home),
        })
    }

    /// Checks that the given path has secure mode.
    pub fn check_secure(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        const SECURE_PERMS: u32 = 0o700;
        const MODE_PERMS_MASK: u32 = 0o777;

        let res = metadata(path);
        if let Ok(md) = res {
           let mode = md.permissions().mode();
           if mode & MODE_PERMS_MASK != SECURE_PERMS {
               eprintln!("warning: path {} has wrong permissions (should be 700)", path.display());
           }
        }
    }

    /// Apply the function `f` to each password in the password directory. The closure is passed
    /// the path to each password file.
    fn map_password_ids<F>(&self, f: F) -> Result<(), Box<Error>> where F: Fn(&str) -> Result<(), Box<Error>> {
        let passwords_dir = self.passwords_dir();
        let itr = WalkDir::new(&passwords_dir);
        for path in itr {
            let mut f_res = Ok(());
            path.map(|entry| {
                let path = entry.path();
                Self::check_secure(path);
                if !path.is_dir() {
                    let stripped = path.strip_prefix(&passwords_dir).unwrap();
                    f_res = f(stripped.to_str().unwrap().trim_right_matches(".toml"));
                }
            })?;
            f_res?;
        }
        Ok(())
    }

    /// The same as `map_password_ids`, but mutably borrows the environment.
    /// Public for testing.
    pub fn map_password_ids_mut<F>(&self, mut f: F) -> Result<(), Box<Error>>
                                   where F: FnMut(&str) -> Result<(), Box<Error>> {
        let passwords_dir = self.passwords_dir();
        let itr = WalkDir::new(&passwords_dir);
        for path in itr {
            let mut f_res = Ok(());
            path.map(|entry| {
                let path = entry.path();
                Self::check_secure(path);
                if !path.is_dir() {
                    let stripped = path.strip_prefix(&passwords_dir).unwrap();
                    f_res = f(stripped.to_str().unwrap().trim_right_matches(".toml"));
                }
            })?;
            f_res?;
        }
        Ok(())
    }

    /// List passwords to stdout.
    /// If `verbose` is true, meta-data is also printed.
    pub fn list_passwords(&self, verbose: bool) -> Result<(), Box<Error>> {
        self.map_password_ids(|pwid| {
            println!("{}", pwid);
            if verbose {
                let pw = EncryptedPassword::from_file(self.password_path(pwid))
                    .map_err(|e| format!("Failed to load password '{}' from file: {}.", pwid, e))?;
                println!("    username: {}", pw.username().unwrap_or(""));
                println!("    email   : {}", pw.email().unwrap_or(""));
                println!("    comment : {}\n", pw.comment().unwrap_or(""));
            }
            Ok(())
        }).map_err(|e| CustomErrorMessage::boxed(format!("Failed to list passwords: {}.", e)) as Box<Error>)
    }

    fn load_password(&self, pwid: &str) -> Result<EncryptedPassword, Box<Error>> {
        let path = self.password_path(pwid);
        Self::check_secure(path.as_path());
        Ok(EncryptedPassword::from_file(path)?)
    }

    fn get_clear_password(&mut self, pwid: &str) -> Result<ClearPassword, String> {
        info!("Loading and decrypting password '{}'", pwid);
        let epw = self.load_password(pwid)
                      .map_err(|e| format!("Failed to load password '{}': {}", pwid, e))?;
        let cpw = epw.decrypt(&mut self.gpg)
                     .map_err(|e| format!("Failed to decrypt password '{}': {}", pwid, e))?;
        Ok(cpw)
    }

    /// Print a password string in the clear to stdout.
    pub fn stdout(&mut self, pwid: &str) -> Result<(), Box<Error>> {
        let pw = self.get_clear_password(pwid)?;
        print!("{}", pw.clear_text());
        Ok(())
    }

    /// Gets the path to the password file from the given password ID.
    fn password_path(&self, pwid: &str) -> PathBuf {
        let mut full_path = self.passwords_dir();
        full_path.push(pwid);
        full_path.set_extension("toml");
        full_path
    }

    /// Add a new password into the password directory with the given password ID.
    pub fn add_password(&mut self, pwid: &str, pw: ClearPassword) -> Result<(), Box<Error>> {
        info!("Adding password '{}'", pwid);
        let full_path = self.password_path(pwid);
        if full_path.exists() {
            return Err(CustomErrorMessage::boxed(format!("Password '{}' already exists", pwid)));
        }

        let dir = full_path.clone();
        let dir_p = dir.parent().unwrap();

        // Create intermediate directories (if necessary).
        let res = DirBuilder::new()
                   .recursive(true)
                   .mode(PROTECTED_MODE)
                   .create(dir_p);
        if let Err(e) = res {
            let msg = format!("Create directory '{}' failed: {}", dir_p.display(), e);
            return Err(CustomErrorMessage::boxed(msg));
        }

        // And commit to disk.
        let epw = pw.encrypt(&mut self.gpg, &self.config.encrypt_to())
                    .map_err(|e| format!("Failed to encrypt: {}", e))?;
        epw.to_disk(full_path)
           .map_err(|e| format!("Failed to write pasword file: {}", e))?;
        Ok(())
    }

    pub fn passwords_dir(&self) -> PathBuf {
        Self::_passwords_dir(&self.state_dir)
    }

    /// Get the password storage directory.
    pub fn _passwords_dir(state_dir: &PathBuf) -> PathBuf {
        let mut passwords_dir = state_dir.clone();
        passwords_dir.push(PASSWORDS_DIR_NAME);
        passwords_dir
    }

    fn get_menu_stdin(&self) -> Result<String, Box<Error>> {
        let mut elems: Vec<String> = Vec::new();
        self.map_password_ids_mut(|pwid| {
            elems.push(String::from(pwid));
            Ok(())
        })?;
        Ok(elems.join("\n"))
    }

    fn notify(&self, msg: &str) -> io::Result<()> {
        if let &Some(ref prog) = self.config.notify_program() {
            info!("Running notify program: {}", prog.display());
            let output = Command::new(prog)
                                 .arg(msg)
                                 .output()?;

            if !output.status.success() {
                let msg = format!("Failed to excute {}", prog.display());
                return Err(io::Error::new(io::ErrorKind::Other, msg.as_str()));
            }
        }
        Ok(())
    }

    /// Invoke a dmenu compatible menu program allowing the user to select a password. The selected
    /// password is loaded into the clipboard.
    pub fn menu(&mut self) -> Result<(), Box<Error>> {
        if self.config.menu_program().is_none() {
            let msg = String::from("No menu program configured or found");
            return Err(CustomErrorMessage::boxed(msg));
        }

        let mut child;
        {
            let menu_prog = self.config.menu_program().as_ref().unwrap();
            info!("Running menu program: {}", menu_prog.display());
            let menu_args = self.config.menu_args();
            let stdin_str = self.get_menu_stdin()
                                .map_err(|e| CustomErrorMessage::boxed(format!("Failed to build dmenu input: {}", e)))?;

            let mut dmenu = Command::new(menu_prog);
            child = dmenu.stdin(Stdio::piped())
                                      .stdout(Stdio::piped())
                                      .args(menu_args)
                                      .spawn()
                                      .map_err(|e| CustomErrorMessage::boxed(format!(
                                                   "Menu program failed: {}: {}", menu_prog.display(), e)))?;

            {
                let pipe = child.stdin.as_mut().unwrap();
                pipe.write_all(&stdin_str.as_bytes()).unwrap();
            }

            let status = child.wait().unwrap();
            if !status.success() {
                let msg = format!("Menu program failed: {}", menu_prog.display());
                return Err(CustomErrorMessage::boxed(msg));
            }
        }

        let mut chosen = String::new();
        child.stdout.unwrap().read_to_string(&mut chosen).unwrap();
        self.clip(chosen.trim())
    }

    /// Load the clipboard with the specified password's decrypted cipher text.
    pub fn clip(&mut self, pwid: &str) -> Result<(), Box<Error>> {
        info!("Send password {} to clipboard", pwid);

        // Instantiate clipboard contexts.
        // We use `X11ClipboardContext` directly as this is a UNIX program.
        let mut pri_clip: X11ClipboardContext<Primary> = X11ClipboardContext::new()
            .map_err(|e| format!("Failed to init 'primary' clipboard: {}", e))?;
        let mut clip_clip: X11ClipboardContext<Clipboard> = X11ClipboardContext::new()
            .map_err(|e| format!("Failed to init 'clipboard' clipboard: {}", e))?;

        let epw = EncryptedPassword::from_file(self.password_path(pwid))
                                    .map_err(|e| format!("Failed to read password '{}' from file: {}", pwid, e))?;

        let pw = epw.decrypt(&mut self.gpg)
                    .map_err(|e| format!("Failed to decrypt password '{}': {}", pwid, e))?;
        let clear_text = pw.clear_text();

        // Load the clipboards.
        pri_clip.set_contents(String::from(clear_text))
                .map_err(|e| format!("Failed to load 'primary' clipboard: {}", e))?;
        clip_clip.set_contents(String::from(clear_text))
                .map_err(|e| format!("Failed to load 'clipboard' clipboard: {}", e))?;

        // Notify the user.
        let mut msg = String::new();
        msg.push_str(&format!("Loaded password `{}' into clipboard\n", pwid));
        msg.push_str(&format!("    username: {}\n", pw.username().unwrap_or("")));
        msg.push_str(&format!("    email   : {}\n", pw.email().unwrap_or("")));
        msg.push_str(&format!("    comment : {}", pw.comment().unwrap_or("")));
        self.notify(&msg)
            .map_err(|e| format!("Failed to notify: {}", e))?;

        // And we have to wait. If we allow the program to exit, the clipboard is cleared.
        let dur = time::Duration::new(1, 0);
        for i in (1..self.config.clipboard_timeout() + 1).rev() {
            print!("{}...", i);
            stdout().flush().unwrap();
            thread::sleep(dur);
        }
        println!("");

        // The clipboards should be cleared when we exit, but just to be certain.
        pri_clip.set_contents(String::from(""))
                .map_err(|e| format!("Failed to clear 'primary' clipboard: {}", e))?;
        clip_clip.set_contents(String::from(""))
                 .map_err(|e| format!("Failed to clear 'clipboard' clipboard: {}", e))?;
        info!("Cleared clipboards");
        self.notify("Cleared clipboards")
            .map_err(|e| format!("Failed to notify: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Tabr, GPG, ClearPassword};
    use config::CONFIG_FILENAME;
    use tempfile::{self, TempDir};
    use std::path::{PathBuf, Path};
    use std::fs::File;
    use std::io::Write;
    use std::collections::HashSet;

    const TEST_KEY_FILENAME: &'static str = "test_key.asc";
    const DEFAULT_CONFIG_TEXT: &'static str = "encrypt_to = [\"745727B1E02B76067B584B593DC6B84E4ACE6921\"]";
    const GPG_CONFIG_FILENAME: &'static str = "gpg.conf";

    /// Everything needed to run tests using using a temporary directories for the state directory and
    /// GnuPG home directory.
    ///
    /// When this falls out of scope the temporary directories are destroyed, so this must live long
    /// enough for the entirety of your test to run.
    struct TestState {
        // The dirs are not used, but their lifetime determines how long they last on disk
        #[allow(dead_code)]
        state_dir: TempDir,
        #[allow(dead_code)]
        gpg_dir: TempDir,
        app: Tabr,
    }

    impl TestState {
        fn new(config_text: Option<&str>) -> Self {
            let state_dir = tempfile::tempdir().unwrap();
            let gpg_dir = tempfile::tempdir().unwrap();

            let config_text = match config_text {
                None => DEFAULT_CONFIG_TEXT,
                Some(s) => s,
            };

            let file_path = PathBuf::from(file!());
            let mut key_path = file_path.parent().unwrap().parent().unwrap().to_owned();
            key_path.push(TEST_KEY_FILENAME);
            GPG::new(Some(gpg_dir.path().to_owned())).import_key(key_path.as_path()).unwrap();

            // We have to force GnuPG to trust our newly imported key, otherwise gpgme will report
            // "unusable key". Of course you would not do this is the real world!
            let mut path = gpg_dir.path().to_owned();
            path.push(GPG_CONFIG_FILENAME);
            let mut fh = File::create(path).unwrap();
            fh.write_all(b"trust-model always").unwrap();

            Self::write_config_file(state_dir.path(), config_text);
            let app = Tabr::new(
                state_dir.path().to_path_buf(),
                Some(gpg_dir.path().to_owned())
            ).unwrap();

            Self {
                state_dir,
                gpg_dir,
                app,
            }
        }

        // Write the specified text into a config file in the specified state directory.
        fn write_config_file(state_dir: &Path, text: &str) {
            let mut path = state_dir.to_owned();
            path.push(CONFIG_FILENAME);
            let mut fh = File::create(path).unwrap();
            fh.write_all(text.as_bytes()).unwrap();
        }

        fn count_passwords(&self) -> u32 {
            let mut count = 0;
            self.app.map_password_ids_mut(|_| {
                count += 1;
                Ok(())
            }).unwrap();
            count
        }
    }

    #[test]
    fn test_empty() {
        let st = TestState::new(None);
        assert_eq!(st.count_passwords(), 0);
    }

    #[test]
    fn test_map1() {
        let mut st = TestState::new(None);
        let pw = ClearPassword::new(None, None, None, "secret");
        st.app.add_password("test123", pw).unwrap();
        assert_eq!(st.count_passwords(), 1);
    }

    #[test]
    fn test_map2() {
        let mut st = TestState::new(None);

        let mut expect = HashSet::new();
        for i in 0..10 {
            let name = format!("pass{}", i);
            let clear_text = format!("secret{}", i);
            let pw = ClearPassword::new(None, None, None, clear_text);
            st.app.add_password(&name, pw).unwrap();
            expect.insert(name);
        }

        let mut got = HashSet::new();
        st.app.map_password_ids_mut(|p| {
            got.insert(p.to_owned());
            Ok(())
        }).unwrap();

        assert_eq!(st.count_passwords(), 10);
        assert_eq!(got, expect);
    }

    #[test]
    fn test_bogus_encrypt_to1() {
        let ctext = "encrypt_to = [\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"]";
        let mut st = TestState::new(Some(ctext));
        let pw = ClearPassword::new(None, None, None, "secret");
        let res = st.app.add_password("test123", pw);
        assert!(res.is_err());
        assert_eq!(res.err().unwrap().to_string(),
                   "Failed to encrypt: Can\'t find GnuPG key \
                   'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'");
    }

    #[test]
    fn test_already_exists() {
        let mut st = TestState::new(None);
        let pw = ClearPassword::new(None, None, None, "secret");
        let pw2 = pw.clone();
        st.app.add_password("abc", pw).unwrap();
        match st.app.add_password("abc", pw2) {
            Err(s) => assert_eq!(s.to_string(), "Password 'abc' already exists"),
            _ => panic!(),
        };
    }

    #[test]
    fn test_load_metadata_encrypted() {
        let pwid = "abc";
        let mut st = TestState::new(None);
        let pw = ClearPassword::new(Some("the_user"), Some("the_email"),
                                    Some("the_comment"), "secret");
        st.app.add_password(pwid, pw).unwrap();

        match st.app.load_password(pwid) {
            Ok(epw) => {
                assert_eq!(epw.username(), Some("the_user"));
                assert_eq!(epw.email(), Some("the_email"));
                assert_eq!(epw.comment(), Some("the_comment"));
            },
            _ => panic!(),
        }
    }

    #[test]
    fn test_load_metadata_decrypted() {
        let pwid = "abc";
        let mut st = TestState::new(None);
        let pw = ClearPassword::new(Some("the_user"), Some("the_email"),
                                    Some("the_comment"), "secret");
        st.app.add_password(pwid, pw).unwrap();

        match st.app.get_clear_password(pwid) {
            Ok(epw) => {
                assert_eq!(epw.username(), Some("the_user"));
                assert_eq!(epw.email(), Some("the_email"));
                assert_eq!(epw.comment(), Some("the_comment"));
            },
            _ => panic!(),
        }
    }

    #[test]
    fn test_decrypt_nonexistent() {
        let mut st = TestState::new(None);
        let expect = "Failed to load password \'woof\': No such file or directory (os error 2)";
        match st.app.get_clear_password("woof") {
            Err(s) => assert_eq!(s, expect),
            _ => panic!(),
        }
    }
}
