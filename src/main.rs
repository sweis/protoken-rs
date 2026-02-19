use std::io::{self, Read as _};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::{Parser, Subcommand};

use protoken::keys::{
    deserialize_signing_key, deserialize_verifying_key, extract_verifying_key,
    serialize_signing_key, serialize_verifying_key, SigningKey as ProtoSigningKey,
};
use protoken::serialize::{deserialize_payload, deserialize_signed_token};
use protoken::sign::{
    compute_key_hash, generate_ed25519_key, generate_hmac_key, generate_mldsa44_key,
    mldsa44_key_hash, sign_ed25519, sign_hmac, sign_mldsa44,
};
use protoken::types::{Algorithm, Claims, KeyIdentifier};
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

    /// Sign a new token. Key is a hex-encoded SigningKey proto.
    Sign {
        /// Key file path (hex-encoded SigningKey proto).
        #[arg(short, long)]
        key: String,

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
        /// Key file path (hex-encoded VerifyingKey or SigningKey proto for HMAC).
        #[arg(short, long)]
        key: String,

        /// Token as hex or base64 string. If omitted, reads from stdin.
        #[arg(short, long)]
        token: Option<String>,
    },

    /// Generate a new key pair.
    /// Outputs JSON with hex-encoded SigningKey and VerifyingKey protos.
    GenerateKey {
        /// Algorithm: "hmac", "ed25519" (default), or "ml-dsa-44"
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
            duration,
            output,
            subject,
            audience,
            scope,
        } => cmd_sign(&key, &duration, &output, subject, audience, scope),
        Command::Verify { key, token } => cmd_verify(&key, token),
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

fn cmd_sign(
    key_path: &str,
    duration_str: &str,
    output_format: &str,
    subject: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_hex_key_file(key_path)?;
    let sk = deserialize_signing_key(&key_bytes)?;

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

    let token_bytes = match sk.algorithm {
        Algorithm::HmacSha256 => sign_hmac(&sk.secret_key, claims)?,
        Algorithm::Ed25519 => {
            let key_id = KeyIdentifier::KeyHash(compute_key_hash(&sk.public_key));
            sign_ed25519(&sk.secret_key, claims, key_id)?
        }
        Algorithm::MlDsa44 => {
            let key_id = mldsa44_key_hash(&sk.public_key)?;
            sign_mldsa44(&sk.secret_key, claims, key_id)?
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

fn cmd_verify(key_path: &str, token_arg: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_hex_key_file(key_path)?;
    let token_bytes = read_token_bytes(token_arg)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is set before Unix epoch (1970-01-01)")?
        .as_secs();

    // Detect algorithm from the token's payload
    let token = deserialize_signed_token(&token_bytes)?;
    let payload = deserialize_payload(&token.payload_bytes)?;

    let verified = match payload.metadata.algorithm {
        Algorithm::HmacSha256 => {
            let sk = deserialize_signing_key(&key_bytes)?;
            verify_hmac(&sk.secret_key, &token_bytes, now)?
        }
        Algorithm::Ed25519 => {
            let vk = deserialize_verifying_key(&key_bytes)?;
            verify_ed25519(&vk.public_key, &token_bytes, now)?
        }
        Algorithm::MlDsa44 => {
            let vk = deserialize_verifying_key(&key_bytes)?;
            verify_mldsa44(&vk.public_key, &token_bytes, now)?
        }
    };

    println!("{}", serde_json::to_string_pretty(&verified)?);
    Ok(())
}

fn cmd_generate_key(algorithm: &str) -> Result<(), Box<dyn std::error::Error>> {
    match algorithm {
        "hmac" => {
            let secret_key = generate_hmac_key();
            let key_hash = compute_key_hash(&secret_key);

            let sk = ProtoSigningKey {
                algorithm: Algorithm::HmacSha256,
                secret_key,
                public_key: Vec::new(),
            };
            let sk_bytes = serialize_signing_key(&sk);

            let output = serde_json::json!({
                "algorithm": "hmac-sha256",
                "signing_key_hex": hex::encode(&sk_bytes),
                "key_hash_hex": hex::encode(key_hash),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "ed25519" => {
            let (seed, pk) = generate_ed25519_key()?;
            let key_hash = compute_key_hash(&pk);

            let sk = ProtoSigningKey {
                algorithm: Algorithm::Ed25519,
                secret_key: seed,
                public_key: pk,
            };
            let sk_bytes = serialize_signing_key(&sk);

            let vk = extract_verifying_key(&sk)?;
            let vk_bytes = serialize_verifying_key(&vk);

            let output = serde_json::json!({
                "algorithm": "ed25519",
                "signing_key_hex": hex::encode(&sk_bytes),
                "verifying_key_hex": hex::encode(&vk_bytes),
                "key_hash_hex": hex::encode(key_hash),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "ml-dsa-44" => {
            let (sk_raw, pk) = generate_mldsa44_key()?;
            let key_hash = compute_key_hash(&pk);

            let sk = ProtoSigningKey {
                algorithm: Algorithm::MlDsa44,
                secret_key: sk_raw,
                public_key: pk,
            };
            let sk_bytes = serialize_signing_key(&sk);

            let vk = extract_verifying_key(&sk)?;
            let vk_bytes = serialize_verifying_key(&vk);

            let output = serde_json::json!({
                "algorithm": "ml-dsa-44",
                "signing_key_hex": hex::encode(&sk_bytes),
                "verifying_key_hex": hex::encode(&vk_bytes),
                "key_hash_hex": hex::encode(key_hash),
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        _ => {
            return Err(format!(
                "unknown algorithm: {algorithm} (use 'hmac', 'ed25519', or 'ml-dsa-44')"
            )
            .into())
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

/// Read a hex-encoded key file and decode it.
/// Rejects files larger than 100 KB to prevent accidental misuse.
fn read_hex_key_file(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > 100_000 {
        return Err(format!("key file too large: {} bytes (max 100,000)", metadata.len()).into());
    }
    let raw = std::fs::read_to_string(path)?;
    Ok(hex::decode(raw.trim())?)
}
