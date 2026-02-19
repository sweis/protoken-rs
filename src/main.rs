use std::io::{self, Read as _};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::pkcs8::DecodePrivateKey;

use protoken::serialize::{deserialize_payload, deserialize_signed_token};
use protoken::sign::{
    compute_key_hash, ed25519_key_hash, generate_ed25519_key, generate_mldsa44_key,
    mldsa44_key_hash, sign_ed25519, sign_hmac, sign_mldsa44, split_mldsa44_key,
};
use protoken::types::{Algorithm, Claims, MLDSA44_PUBLIC_KEY_LEN, MLDSA44_SIGNING_KEY_LEN};
use protoken::verify::{verify_ed25519, verify_hmac, verify_mldsa44};

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

    /// Sign a new token. Algorithm is detected from the key format:
    /// PKCS#8 DER → Ed25519, 3872-byte combined key → ML-DSA-44, otherwise → HMAC.
    Sign {
        /// Key file path. HMAC: raw bytes; Ed25519: PKCS#8 DER; ML-DSA-44: combined key (3872 B).
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
    /// Algorithm is detected from the token.
    Verify {
        /// Key file path. HMAC: raw bytes; Ed25519: 32-byte public key; ML-DSA-44: 1312-byte public key.
        #[arg(short, long)]
        key: String,

        /// Interpret the key file as hex-encoded.
        #[arg(long, default_value_t = false)]
        hex_key: bool,

        /// Token as hex or base64 string. If omitted, reads from stdin.
        #[arg(short, long)]
        token: Option<String>,
    },

    /// Generate a new key pair.
    /// For Ed25519: outputs PKCS#8 private key and public key as hex.
    /// For ML-DSA-44: outputs signing key, public key, and key hash as hex.
    GenerateKey {
        /// Algorithm: "ed25519" (default) or "ml-dsa-44"
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Inspect { token } => cmd_inspect(token),
        Command::Sign {
            key,
            hex_key,
            duration,
            output,
            subject,
            audience,
            scope,
        } => cmd_sign(&key, hex_key, &duration, &output, subject, audience, scope),
        Command::Verify {
            key,
            hex_key,
            token,
        } => cmd_verify(&key, hex_key, token),
        Command::GenerateKey { algorithm } => cmd_generate_key(&algorithm),
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

/// ML-DSA-44 combined key length: signing key (2560) + public key (1312).
const MLDSA44_COMBINED_KEY_LEN: usize = MLDSA44_SIGNING_KEY_LEN + MLDSA44_PUBLIC_KEY_LEN;

/// Detect the signing algorithm from key bytes.
/// - Valid PKCS#8 DER for Ed25519 → Ed25519
/// - Exactly 3872 bytes → ML-DSA-44
/// - Otherwise → HMAC-SHA256
fn detect_signing_algorithm(key_bytes: &[u8]) -> Algorithm {
    if key_bytes.len() == MLDSA44_COMBINED_KEY_LEN {
        return Algorithm::MlDsa44;
    }
    if ed25519_dalek::SigningKey::from_pkcs8_der(key_bytes).is_ok() {
        return Algorithm::Ed25519;
    }
    Algorithm::HmacSha256
}

fn cmd_sign(
    key_path: &str,
    hex_key: bool,
    duration_str: &str,
    output_format: &str,
    subject: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_key_file(key_path, hex_key)?;
    let algorithm = detect_signing_algorithm(&key_bytes);

    let duration: std::time::Duration = duration_str
        .parse::<humantime::Duration>()
        .map_err(|e| format!("invalid duration '{duration_str}': {e}"))?
        .into();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is set before Unix epoch (1970-01-01)")?
        .as_secs();

    let expires_at = now
        .checked_add(duration.as_secs())
        .ok_or("duration overflow")?;

    let claims = Claims {
        expires_at,
        not_before: now,
        issued_at: now,
        subject: subject.unwrap_or_default(),
        audience: audience.unwrap_or_default(),
        scopes,
    };

    let token_bytes = match algorithm {
        Algorithm::HmacSha256 => sign_hmac(&key_bytes, claims)?,
        Algorithm::Ed25519 => {
            let key_id = ed25519_key_hash(&key_bytes)?;
            sign_ed25519(&key_bytes, claims, key_id)?
        }
        Algorithm::MlDsa44 => {
            let (sk, pk) = split_mldsa44_key(&key_bytes)?;
            let key_id = mldsa44_key_hash(pk)?;
            sign_mldsa44(sk, claims, key_id)?
        }
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
    key_path: &str,
    hex_key: bool,
    token_arg: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_key_file(key_path, hex_key)?;
    let token_bytes = read_token_bytes(token_arg)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is set before Unix epoch (1970-01-01)")?
        .as_secs();

    // Detect algorithm from the token's payload
    let token = deserialize_signed_token(&token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    let verified = match payload.metadata.algorithm {
        Algorithm::HmacSha256 => verify_hmac(&key_bytes, &token_bytes, now)?,
        Algorithm::Ed25519 => verify_ed25519(&key_bytes, &token_bytes, now)?,
        Algorithm::MlDsa44 => verify_mldsa44(&key_bytes, &token_bytes, now)?,
    };

    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

fn cmd_generate_key(algorithm: &str) -> Result<(), Box<dyn std::error::Error>> {
    match algorithm {
        "ed25519" => {
            let pkcs8 = generate_ed25519_key()?;
            let signing_key = ed25519_dalek::SigningKey::from_pkcs8_der(&pkcs8)
                .map_err(|e| format!("key parse failed: {e}"))?;

            let public_key_bytes = signing_key.verifying_key().to_bytes();
            let key_hash = compute_key_hash(&public_key_bytes);

            let output = serde_json::json!({
                "algorithm": "ed25519",
                "private_key_pkcs8_hex": hex::encode(&pkcs8),
                "public_key_hex": hex::encode(public_key_bytes),
                "key_hash_hex": hex::encode(key_hash),
            });

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "ml-dsa-44" => {
            let (sk, pk) = generate_mldsa44_key()?;
            let key_hash = compute_key_hash(&pk);

            // Combined key (SK || PK) for use with --key flag in sign command
            let mut combined = sk.clone();
            combined.extend_from_slice(&pk);

            let output = serde_json::json!({
                "algorithm": "ml-dsa-44",
                "combined_key_hex": hex::encode(&combined),
                "public_key_hex": hex::encode(&pk),
                "key_hash_hex": hex::encode(key_hash),
                "signing_key_bytes": sk.len(),
                "public_key_bytes": pk.len(),
            });

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            return Err(
                format!("unknown algorithm: {algorithm} (use 'ed25519' or 'ml-dsa-44')").into(),
            )
        }
    }

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
        let hex_str = String::from_utf8(raw).map_err(|_| "hex key file is not valid UTF-8")?;
        Ok(hex::decode(hex_str.trim())?)
    } else {
        Ok(raw)
    }
}
