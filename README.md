# Tabr

Tabr is a simple password manager.

## Features

 * Written in stable-compatible Rust.
 * Backed by GnuPG.
 * Command-line interface and Dmenu GUI.
 * Clipboard support.
 * Notify-send support.

## Getting Started

Run `tabr` with no arguments for help setting up a config file.

Run `tabr --help` for usage information.

## Examples

Add a password:
```
tabr add mypassword
```

Add a password specifying a username, email address and a comment:
```
tabr add -u myusername -e myemail@me.com -c "account created 2018-01-01" mypassword
```

Put the cleartext of a password into the clipboard:
```
tabr clip mypassword
```


## The Name

In Frank Herbert's Dune, Sietch Tabr is one of the primary hideouts of the
Fremen people of Arrakis.
