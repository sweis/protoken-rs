use std::io::{self, Read as _};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::{Parser, Subcommand};
use ring::signature::{Ed25519KeyPair, KeyPair};

use protoken::serialize::{deserialize_payload, deserialize_signed_token};
use protoken::sign::{
    compute_key_hash, ed25519_key_hash, generate_ed25519_key, sign_ed25519, sign_hmac,
};
use protoken::types::Claims;
use protoken::verify::{verify_ed25519, verify_hmac};

#[derive(Parser)]
#[command(name = "protoken", about = "Protobuf-inspired signed tokens")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a token: deserialize and display as JSON.
    /// Reads hex or base64 from --token or stdin.
    Inspect {
        /// Token as hex or base64 string. If omitted, reads from stdin.
        #[arg(short, long)]
        token: Option<String>,
    },

    /// Sign a new token with the given key and duration.
    Sign {
        /// Algorithm: "hmac" or "ed25519"
        #[arg(short, long)]
        algorithm: String,

        /// Key file path. For HMAC: raw key bytes (or hex with --hex-key).
        /// For Ed25519: PKCS#8 DER file.
        #[arg(short, long)]
        key: String,

        /// Interpret the key file as hex-encoded.
        #[arg(long, default_value_t = false)]
        hex_key: bool,

        /// Token validity duration (e.g. "4d", "1h", "30m").
        #[arg(short, long)]
        duration: String,

        /// Output format: "hex" or "base64"
        #[arg(short, long, default_value = "base64")]
        output: String,

        /// Subject identifier (optional)
        #[arg(long)]
        subject: Option<String>,

        /// Audience identifier (optional)
        #[arg(long)]
        audience: Option<String>,

        /// Scope entries (repeatable, e.g. --scope read --scope write)
        #[arg(long)]
        scope: Vec<String>,
    },

    /// Verify a signed token against a key and current time.
    Verify {
        /// Algorithm: "hmac" or "ed25519"
        #[arg(short, long)]
        algorithm: String,

        /// Key file path. For HMAC: raw key bytes.
        /// For Ed25519: raw 32-byte public key.
        #[arg(short, long)]
        key: String,

        /// Interpret the key file as hex-encoded.
        #[arg(long, default_value_t = false)]
        hex_key: bool,

        /// Token as hex or base64 string. If omitted, reads from stdin.
        #[arg(short, long)]
        token: Option<String>,
    },

    /// Generate a new Ed25519 key pair. Outputs PKCS#8 private key
    /// and the public key, both as hex.
    GenerateKey,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Inspect { token } => cmd_inspect(token),
        Command::Sign {
            algorithm,
            key,
            hex_key,
            duration,
            output,
            subject,
            audience,
            scope,
        } => cmd_sign(&algorithm, &key, hex_key, &duration, &output, subject, audience, scope),
        Command::Verify {
            algorithm,
            key,
            hex_key,
            token,
        } => cmd_verify(&algorithm, &key, hex_key, token),
        Command::GenerateKey => cmd_generate_key(),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_inspect(token_arg: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let token_bytes = read_token_bytes(token_arg)?;

    // Try as SignedToken first, fall back to Payload
    match deserialize_signed_token(&token_bytes) {
        Ok(token) => {
            let payload = deserialize_payload(&token.payload_bytes)?;
            let output = serde_json::json!({
                "type": "SignedToken",
                "payload": payload,
                "signature_hex": hex::encode(&token.signature),
                "total_bytes": token_bytes.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Err(_) => match deserialize_payload(&token_bytes) {
            Ok(payload) => {
                let output = serde_json::json!({
                    "type": "Payload",
                    "payload": payload,
                    "total_bytes": token_bytes.len(),
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            }
            Err(e) => {
                return Err(format!("could not parse as SignedToken or Payload: {e}").into());
            }
        },
    }

    Ok(())
}

fn cmd_sign(
    algorithm: &str,
    key_path: &str,
    hex_key: bool,
    duration_str: &str,
    output_format: &str,
    subject: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_key_file(key_path, hex_key)?;

    let duration: std::time::Duration = duration_str
        .parse::<humantime::Duration>()
        .map_err(|e| format!("invalid duration '{duration_str}': {e}"))?
        .into();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();

    let expires_at = now
        .checked_add(duration.as_secs())
        .ok_or("duration overflow")?;

    let claims = Claims {
        expires_at,
        not_before: now,
        issued_at: now,
        subject: subject.map(|s| s.into_bytes()).unwrap_or_default(),
        audience: audience.map(|s| s.into_bytes()).unwrap_or_default(),
        scopes,
    };

    let token_bytes = match algorithm {
        "hmac" => sign_hmac(&key_bytes, claims),
        "ed25519" => {
            let key_id = ed25519_key_hash(&key_bytes)?;
            sign_ed25519(&key_bytes, claims, key_id)?
        }
        _ => return Err(format!("unknown algorithm: {algorithm}").into()),
    };

    match output_format {
        "hex" => println!("{}", hex::encode(&token_bytes)),
        "base64" => {
            println!(
                "{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes)
            );
        }
        _ => return Err(format!("unknown output format: {output_format}").into()),
    }

    Ok(())
}

fn cmd_verify(
    algorithm: &str,
    key_path: &str,
    hex_key: bool,
    token_arg: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_key_file(key_path, hex_key)?;
    let token_bytes = read_token_bytes(token_arg)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_secs();

    let verified = match algorithm {
        "hmac" => verify_hmac(&key_bytes, &token_bytes, now)?,
        "ed25519" => verify_ed25519(&key_bytes, &token_bytes, now)?,
        _ => {
            return Err(
                format!("unknown algorithm: {algorithm} (use 'hmac' or 'ed25519')").into(),
            )
        }
    };

    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

fn cmd_generate_key() -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = generate_ed25519_key()?;
    let key_pair =
        Ed25519KeyPair::from_pkcs8(&pkcs8).map_err(|e| format!("key parse failed: {e}"))?;

    let public_key_bytes = key_pair.public_key().as_ref();
    let key_hash = compute_key_hash(public_key_bytes);

    let output = serde_json::json!({
        "private_key_pkcs8_hex": hex::encode(&pkcs8),
        "public_key_hex": hex::encode(public_key_bytes),
        "key_hash_hex": hex::encode(key_hash),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Read token bytes from a CLI argument or stdin, decoding hex or base64.
fn read_token_bytes(token_arg: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let input = match token_arg {
        Some(s) => s.trim().to_string(),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf.trim().to_string()
        }
    };

    // Try hex first, then base64
    if let Ok(bytes) = hex::decode(&input) {
        return Ok(bytes);
    }

    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&input) {
        return Ok(bytes);
    }

    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&input) {
        return Ok(bytes);
    }

    Err("could not decode token as hex or base64".into())
}

/// Read key bytes from a file, optionally hex-decoding.
fn read_key_file(path: &str, hex_encoded: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    if hex_encoded {
        let hex_str =
            String::from_utf8(raw).map_err(|_| "hex key file is not valid UTF-8")?;
        Ok(hex::decode(hex_str.trim())?)
    } else {
        Ok(raw)
    }
}
