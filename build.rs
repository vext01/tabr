fn main() {
    // Clipboard needs libxcb, which is in a non-standard path on OpenBSD.
    if cfg!(target_os = "openbsd") {
        println!("cargo:rustc-link-search=/usr/X11R6/lib");
    }

    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu/");
    }
}
