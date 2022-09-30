fn cold_release() -> Result<(), String> {
    use std::{env, fs::create_dir_all, path::Path};

    use generate_message::{full_run, parser::Command};

    let android_root = env::var_os("ANDROID_ROOT_DIR");
    if let Some(v) = android_root {
        let database_path = env::var_os("POLKADOT_DB_PATH");
        if let Some(y) = database_path {
            let cold_release_dir =
                Path::new(&v).join(&y);
            let command = Command::MakeColdRelease {
                path: Some(cold_release_dir),
            };
            full_run(command).map_err(|e| format!("{}", e))?;
        }
    } else {
        let command = Command::MakeColdRelease {
            path: None,
        };

        full_run(command).map_err(|e| format!("{}", e))?;
    }

    Ok(())
}

// #[cfg(target_os = "ios")]
// fn cold_release() -> Result<(), String> {
//     Ok(())
// }

fn main() -> Result<(), String> {
    // We do not need uniffi now;

    // println!("cargo:rerun-if-changed=./src/signer.udl");
    // uniffi_build::generate_scaffolding("./src/signer.udl").unwrap();
    cold_release()
}
