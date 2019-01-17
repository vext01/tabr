/// haveibeenpwned.com password checking.
///
/// Documented here:
/// https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange

use sha1::Sha1;
use std::io;
use std::error::Error;
use knock::{HTTP, response::Response};
use secstr::SecStr;

static REQ_BASE: &str = "https://api.pwnedpasswords.com/range/";
static PREFIX_LEN: usize = 5;

fn handle_ok_response(response: &Response, hash_sufx: &str) -> Result<bool, io::Error> {
    for line in response.body.lines() {
        let check_sufx = match line.split(":").next() {
            Some(elem) => elem.to_ascii_lowercase(),
            _ => return Err(io::Error::new(
                io::ErrorKind::Other, "missing hash suffix in HTTP response")),
        };

        if check_sufx.len() != hash_sufx.len() {
            return Err(io::Error::new(
                io::ErrorKind::Other, "hash suffix in HTTP response has wrong length"));
        }

        if check_sufx == hash_sufx {
            // pwned.
            return Ok(true);
        }
    }
    Ok(false)
}

/// Returns `Ok(true)` if the has for `pw` is in the pwnedpasswords.com database, or `Ok(false)` if
/// it is not.
pub fn is_pwned(pw: &SecStr) -> Result<bool, Box<Error>> {
    let hash = Sha1::from(pw.unsecure()).digest().to_string().to_ascii_lowercase();
    let hash_prefix = &hash[..PREFIX_LEN];
    let mut req_url = String::from(REQ_BASE);
    req_url.push_str(hash_prefix);

    let mut http = HTTP::new(&req_url)?;
    let response = http.get().send()?;

    // According to the docs, only 200 should happen on the range API. It's not even rate limited.
    match response.status {
        200 => Ok(handle_ok_response(&response, &hash[PREFIX_LEN..])?),
        _ => Err(Box::new(io::Error::new(
            io::ErrorKind::Other, format!("unhandled HTTP status: {}", response.status)))),
    }
}
