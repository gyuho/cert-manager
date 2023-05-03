use std::{
    env::args,
    fs,
    process::{Command, Stdio},
};

use cert_manager::x509;

/// cargo run --example x509 [SIGNATURE ALGORITHM]
///
/// cargo run --example x509
///
/// # for mac
/// cargo run --example x509 PKCS_RSA_SHA256
///
/// # for linux
/// cargo run --example x509 PKCS_ECDSA_P256_SHA256
///
/// cargo run --example x509 PKCS_ECDSA_P384_SHA384
fn main() {
    // ref. https://github.com/env-logger-rs/env_logger/issues/47
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
    );

    let sig_algo = if let Some(s) = args().nth(1) {
        Some(s)
    } else {
        None
    };
    let cert_params = x509::default_params(sig_algo, None, false).unwrap();

    let key_path = random_manager::tmp_path(10, Some(".pem.key")).unwrap();
    let cert_path = random_manager::tmp_path(10, Some(".pem.cert")).unwrap();
    x509::generate_and_write_pem(Some(cert_params), &key_path, &cert_path).unwrap();

    let (k, c) = x509::load_pem_to_vec(&key_path, &cert_path).unwrap();
    let key_contents = fs::read(&key_path).unwrap();
    assert_eq!(k, key_contents);
    let cert_contents = fs::read(&cert_path).unwrap();
    assert_eq!(c, cert_contents);

    let openssl_args = vec![
        "x509".to_string(),
        "-in".to_string(),
        cert_path.to_string(),
        "-text".to_string(),
        "-noout".to_string(),
    ];
    let openssl_cmd = Command::new("openssl")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .args(openssl_args.clone())
        .spawn()
        .unwrap();
    log::info!(
        "\nopenssl {}\n(PID {})\n",
        openssl_args.join(" "),
        openssl_cmd.id(),
    );
    let output = openssl_cmd.wait_with_output().unwrap();
    log::info!(
        "openssl output:\n{}\n",
        String::from_utf8(output.stdout).unwrap()
    );
}
