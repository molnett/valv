use std::env;
use std::error::Error;
use std::process::{exit, Command};
fn main() -> Result<(), Box<dyn Error>> {
    // We do not want to perform this action for a CICD release build.
    if Ok("debug".to_owned()) == env::var("PROFILE") {
        #[allow(clippy::unwrap_used)]
        let status = Command::new("buf")
            .arg("generate")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .status()
            .unwrap();

        if !status.success() {
            exit(status.code().unwrap_or(-1))
        }
    }

    Ok(())
}
