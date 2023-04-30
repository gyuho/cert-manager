use std::{
    fs,
    process::{Command, Stdio},
};

use cert_manager::x509;

/// cargo run --example x509
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let key_path = random_manager::tmp_path(10, Some(".key")).unwrap();
    let cert_path = random_manager::tmp_path(10, Some(".pem")).unwrap();

    x509::generate_and_write_pem(None, &key_path, &cert_path).unwrap();
    x509::load_pem_to_vec(&key_path, &cert_path).unwrap();

    let key_contents = fs::read(&key_path).unwrap();
    let key_contents = String::from_utf8(key_contents.to_vec()).unwrap();
    log::info!("key {}", key_contents);
    log::info!("key: {} bytes", key_contents.len());

    // openssl x509 -in [cert_path] -text -noout
    let cert_contents = fs::read(&cert_path).unwrap();
    let cert_contents = String::from_utf8(cert_contents.to_vec()).unwrap();
    log::info!("cert {}", cert_contents);
    log::info!("cert: {} bytes", cert_contents.len());

    let openssl_args = vec![
        "x509".to_string(),
        "-in".to_string(),
        cert_path.to_string(),
        "-text".to_string(),
        "-noout".to_string(),
    ];
    let openssl_cmd = Command::new("openssl")
        .stderr(Stdio::inherit())
        .stdout(Stdio::inherit())
        .args(openssl_args)
        .spawn()
        .unwrap();
    log::info!("spawned openssl with PID {}", openssl_cmd.id());
    let res = openssl_cmd.wait_with_output();
    match res {
        Ok(output) => {
            log::info!(
                "openssl output:\n{}\n",
                String::from_utf8(output.stdout).unwrap()
            )
        }
        Err(e) => {
            log::warn!("failed to run openssl {}", e)
        }
    }
}
