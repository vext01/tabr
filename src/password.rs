use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::path::PathBuf;
use toml;
use gpg::{GPG};
use std::os::unix::fs::OpenOptionsExt;
use std::convert::Into;
use PROTECTED_MODE;
use std::error::Error;

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedPassword {
    username: Option<String>,       // Username associated with the password.
    email: Option<String>,          // Email address assciated with the password.
    comment: Option<String>,        // Any comments the user may wish to include.
    cipher_text: String,            // The encrypted password itself.
}

/// An encrypted password and its meta-data.
impl EncryptedPassword {
    pub fn new<A>(username: Option<A>,
                  email: Option<A>,
                  comment: Option<A>,
                  cipher_text: A) -> Self  where A: Into<String> {
        Self {
            username: username.map(|a| a.into()),
            email: email.map(|a| a.into()),
            comment: comment.map(|a| a.into()),
            cipher_text: cipher_text.into(),
        }
    }

    /// Write a password to disk. If `new` is `true` then the on-disk file must not already exist.
    pub fn to_disk(&self, path: PathBuf, new: bool) -> Result<(), Box<Error>> {
        let tml = toml::to_vec(self)?;
        let mut opts = OpenOptions::new();
        opts.write(true)
            .mode(PROTECTED_MODE)
            .truncate(true);

        if new {
            opts.create_new(true);
        }

        let mut pw_file = opts.open(path)?;
        Ok(pw_file.write_all(&tml)?)
    }

    pub fn username<'a>(&'a self) -> Option<&'a str> {
        self.username.as_ref().map(|s| s.as_str())
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_ref().map(|s| s.as_str())
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|s| s.as_str())
    }

    /// Reads a password in from the given filesystem path.
    pub fn from_file(path: PathBuf) -> Result<Self, Box<Error>> {
        let mut fh = File::open(path)?;
        let mut pw_s: String = String::new();
        fh.read_to_string(&mut pw_s)?;
        Ok(toml::from_str(&pw_s)?)
    }

    /// Consumes and decrypts the password returning a `ClearPassword`.
    pub fn decrypt(self, gpg: &mut GPG) -> Result<ClearPassword, Box<Error>> {
        let clear_text = gpg.decrypt_string(&self.cipher_text)?;
        Ok(ClearPassword {
            username: self.username,
            email: self.email,
            comment: self.comment,
            clear_text: clear_text,
        })
    }
}


/// A clear text password and its meta-data.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClearPassword {
    username: Option<String>,       // Username associated with the password.
    email: Option<String>,          // Email address associated with the password.
    comment: Option<String>,        // Any comments the user may wish to include.
    clear_text: String,             // The password text in the clear.
}

/// An unencrypted password and its meta-data.
impl ClearPassword {
    pub fn new<A>(username: Option<A>,
                  email: Option<A>,
                  comment: Option<A>,
                  clear_text: A) -> Self where A: Into<String> {
        Self {
            username: username.map(|a| a.into()),
            email: email.map(|a| a.into()),
            comment: comment.map(|a| a.into()),
            clear_text: clear_text.into(),
        }
    }

    pub fn clear_text(&self) -> &str {
        &self.clear_text
    }

    pub fn new_clear_text<A>(&mut self, clear_text: A) where A: Into<String> {
        self.clear_text = clear_text.into();
    }

    /// Consumes and encrypts the password returning an `EncryptedPassword`.
    pub fn encrypt(self, gpg: &mut GPG, encrypt_to: &Vec<String>)
                   -> Result<EncryptedPassword, Box<Error>>  {
        let cipher_text = gpg.encrypt_string(&self.clear_text, encrypt_to)?;
        Ok(EncryptedPassword::new(self.username,
                               self.email,
                               self.comment,
                               cipher_text))
    }

    pub fn username<'a>(&'a self) -> Option<&'a str> {
        self.username.as_ref().map(|s| s.as_str())
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_ref().map(|s| s.as_str())
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|s| s.as_str())
    }

    pub fn new_username<A>(&mut self, username: Option<A>) where A: Into<String> {
        self.username = username.map(|u| u.into());
    }

    pub fn new_email<A>(&mut self, email: Option<A>) where A: Into<String> {
        self.email = email.map(|e| e.into());
    }

    pub fn new_comment<A>(&mut self, comment: Option<A>) where A: Into<String> {
        self.comment = comment.map(|c| c.into());
    }
}

/// A password edit description. Here a `None` means "no change".
/// The fields have the same meaning as `ClearPassword`. Unlike `ClearPassword`, all fields are
/// optional, since the user may choose to not change anything.
#[derive(Debug)]
pub struct PasswordEdit {
    username: Option<String>,
    email: Option<String>,
    comment: Option<String>,
    clear_text: Option<String>,
}

impl PasswordEdit {
    pub fn new<A>(username: Option<A>,
                  email: Option<A>,
                  comment: Option<A>,
                  clear_text: Option<A>) -> Self where A: Into<String> {
        Self {
            username: username.map(|a| a.into()),
            email: email.map(|a| a.into()),
            comment: comment.map(|a| a.into()),
            clear_text: clear_text.map(|a| a.into()),
        }
    }

    pub fn clear_text(&self) -> Option<&str> {
        self.clear_text.as_ref().map(|s| s.as_str())
    }

    pub fn username<'a>(&'a self) -> Option<&'a str> {
        self.username.as_ref().map(|s| s.as_str())
    }

    pub fn email(&self) -> Option<&str> {
        self.email.as_ref().map(|s| s.as_str())
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_ref().map(|s| s.as_str())
    }
}
