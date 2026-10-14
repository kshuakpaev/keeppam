#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    if let Err(err) = keeppam_endpoint_agent::run_from_env() {
        eprintln!("endpoint-agent: {err}");
        std::process::exit(1);
    }
}
