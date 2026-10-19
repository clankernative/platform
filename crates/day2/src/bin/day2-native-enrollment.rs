//! Fixed node provisioner / private child issuer. No caller paths, PIDs, keys,
//! runtime methods or callbacks are accepted at this executable boundary.
#![forbid(unsafe_code)]

fn main() {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let issuer = match arguments.as_slice() {
        [] => false,
        [mode] if mode == "issuer" => true,
        _ => {
            eprintln!("day2-native-enrollment refused");
            std::process::exit(1);
        }
    };
    if day2::deployment::run_native_enrollment(issuer).is_err() {
        eprintln!("day2-native-enrollment refused or stopped");
        std::process::exit(1);
    }
}
