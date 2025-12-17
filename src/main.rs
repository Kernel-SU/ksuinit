mod loader;

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <ko_file>", args[0]);
        return ExitCode::from(1);
    }

    let ko_path = &args[1];

    match loader::load_module(ko_path) {
        Ok(_) => {
            println!("Module {} loaded successfully", ko_path);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to load module {}: {:?}", ko_path, e);
            ExitCode::FAILURE
        }
    }
}
