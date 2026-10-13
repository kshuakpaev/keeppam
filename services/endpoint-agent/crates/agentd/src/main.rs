fn main() {
    if let Err(err) = keeppam_agentd::run_from_env() {
        eprintln!("agentd: {err:#}");
        std::process::exit(1);
    }
}
