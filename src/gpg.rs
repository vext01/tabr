use gpgme::{Context, Protocol};
use gpgme::Data;
use std::path::{Path, PathBuf};
use std::ffi::CString;
use std::error::Error;
use std::fmt::{self, Formatter, Display};
use secstr::SecStr;

/// Encapsulates GnuPG operations, lazily initialising gpgme as necessary.
pub struct GPG {
    ctx: Option<Context>,
    gnupg_home: Option<PathBuf>,
}

#[derive(Debug)]
enum RecipientError {
    CantFindKey(String),
    CantEncryptTo(String),
}

impl Error for RecipientError {
    fn description(&self) -> &str {
        "Recipient error"
    }
}

impl Display for RecipientError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            &RecipientError::CantFindKey(ref k) => write!(f, "Can't find GnuPG key '{}'", k),
            &RecipientError::CantEncryptTo(ref k) => write!(f, "Can't encrypt to GnuPG key '{}'", k),
        }
    }
}

impl GPG {
    pub fn new(gnupg_home: Option<PathBuf>) -> Self {
        Self {
            ctx: None,
            gnupg_home: gnupg_home,
        }
    }

    /// Get a reference to a gpgme context, initialising one if necessary.
    fn ctx(&mut self) -> &mut Context {
        match self.ctx {
            Some(ref mut ctx) => ctx, // Already initialised.
            None => {
                let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
                // Override the GnuPG home dir (used in tests).
                if let Some(ref path) = self.gnupg_home {
                    println!("Override: {}", path.display());
                    ctx.set_engine_home_dir(path.to_str().unwrap()).unwrap();
                }
                ctx.set_armor(true);
                self.ctx = Some(ctx);
                self.ctx.as_mut().unwrap()
            },
        }
    }

    /// Encrypt a cleartext string.
    pub fn encrypt_string(&mut self, clear_text: &SecStr,
                          encrypt_to: &Vec<String>) -> Result<String, Box<Error>> {
        let ctx = self.ctx();
        let mut keys = Vec::new();
        for fingerprint in encrypt_to {
            match ctx.find_key(fingerprint) {
                Ok(key) => {
                    if !key.can_encrypt() {
                        return Err(Box::new(RecipientError::CantEncryptTo(fingerprint.to_owned())));
                    }
                    keys.push(key);
                },
                _ => return Err(Box::new(RecipientError::CantFindKey(fingerprint.to_owned()))),
            }
        }

        let mut output = Vec::new();
        ctx.encrypt(&keys, clear_text.unsecure(), &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    /// Decrypt a chipertext string.
    pub fn decrypt_string(&mut self, cipher_text: &str) -> Result<SecStr, Box<Error>> {
        let ctx = self.ctx();
        let mut clear_text_bytes = Vec::new();
        ctx.decrypt(cipher_text, &mut clear_text_bytes)?;
        Ok(SecStr::new(clear_text_bytes))
    }

    /// Import a keypair (used in integration tests).
    pub fn import_key(&mut self, path: &Path) -> Result<(), Box<Error>> {
        let ctx = self.ctx();
        let path_s = match path.to_str() {
            Some(p) => p,
            None => Err(format!("Failed to interpret import key path"))?,
        };
        let mut data = Data::load(CString::new(path_s)?)?;
        ctx.import(&mut data)?;
        Ok(())
    }
}
