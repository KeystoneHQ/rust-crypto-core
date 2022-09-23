pub mod common;
use crate::common::{assert_cmd_stdout, assert_files_eq, setup};

use std::path::PathBuf;
use tempfile::tempdir;
use generate_message::parser::{Command, Show};

#[test]
fn it_loads_metadata() {
    let files_dir = tempdir().unwrap();
    setup(&files_dir);
    let result = generate_message::full_run(Command::Show { s: Show::Metadata, db_path: PathBuf::from(files_dir.path()) });
    println!("{:?}", result);
    let cmd = format!(
        "load-metadata -f -a --hot-db-path {0} --files-dir {0}",
        files_dir.path().to_string_lossy()
    );
    assert_cmd_stdout(&cmd, "");

    let result_file = files_dir.path().join("sign_me_load_metadata_polkadotV30");
    let expected_file = PathBuf::from("./tests/for_tests/load_metadata_polkadotV30");
    let result = generate_message::full_run(Command::Show { s: Show::Metadata, db_path: PathBuf::from(files_dir.path()) });
    println!("{:?}", result);
    assert_files_eq(&result_file, &expected_file);
}
