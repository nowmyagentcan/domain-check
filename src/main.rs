fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("domain-check {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("Usage: domain-check --version");
            std::process::exit(2);
        }
    }
}
