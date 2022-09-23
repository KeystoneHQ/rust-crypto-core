use std::fmt::format;

// #[cfg(not(target_os = "ios"))]
fn cold_release() -> Result<(), String> {
    use std::{env, fs::create_dir_all, path::Path};

    use generate_message::{full_run, parser::Command};

    let android_root = env::var_os("ANDROID_ROOT_DIR").ok_or_else(|| format!("No env variable ANDROID_ROOT_DIR found"))?;
    let database_path = env::var_os("POLKADOT_DB_PATH").ok_or_else(|| format!("No env variable POLKADOT_DB_PATH found"))?;
    let cold_release_dir =
        Path::new(&android_root).join(&database_path);
    create_dir_all(&cold_release_dir).unwrap();
    let command = Command::MakeColdRelease {
        path: Some(cold_release_dir),
    };

    full_run(command).map_err(|e| format!("{}", e))?;

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
    // Ok(())
}
