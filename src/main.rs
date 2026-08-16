fn main() {
    let options = linyaps_box::cli::parse();
    if let Err(error) = linyaps_box::logging::initialize(&options.global) {
        eprintln!("failed to initialize logger: {error:#}");
        std::process::exit(1);
    }
    match linyaps_box::runtime::dispatch(&options.command, &options.global) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            tracing::error!(function = "main", "Error: {error:#}");
            std::process::exit(1);
        }
    }
}
