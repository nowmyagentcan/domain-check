fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => println!("{}", domain_check::version()),
        _ => {
            eprintln!("Usage: domain-check --version");
            std::process::exit(2);
        }
    }
}
