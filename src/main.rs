use std::io::{self, Read as _};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};
use colored::Colorize;
use zeroize::Zeroizing;

use protoken::keys::{
    deserialize_signing_key, deserialize_verifying_key, extract_verifying_key,
    serialize_signing_key, serialize_verifying_key, SigningKey as ProtoSigningKey,
};
use protoken::serialize::{deserialize_payload, deserialize_signed_token};
use protoken::sign::{
    compute_key_hash, generate_ed25519_key, generate_hmac_key, generate_mldsa44_key,
    mldsa44_key_hash, sign_ed25519, sign_groth16, sign_groth16_hybrid, sign_hmac, sign_mldsa44,
};
use protoken::snark;
use protoken::types::{Algorithm, Claims, KeyIdentifier, Payload};
use protoken::verify::{
    verify_ed25519, verify_groth16, verify_groth16_hybrid, verify_hmac, verify_mldsa44,
};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Cyan.on_default())
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default());

#[derive(Parser)]
#[command(
    name = "protoken",
    about = "Protobuf-inspired signed tokens",
    flatten_help = true,
    styles = STYLES
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new signing key (base64-encoded SigningKey proto).
    GenerateKey {
        /// Algorithm: "hmac", "ed25519" (default), "ml-dsa-44", "groth16", or "groth16-hybrid".
        #[arg(short, long, default_value = "ed25519")]
        algorithm: String,
    },

    /// Get the verifying key from a signing key.
    GetVerifyingKey {
        /// Signing key file, or "-" for stdin.
        keyfile: String,
    },

    /// Run Groth16 trusted setup (one-time, produces proving + verifying keys).
    SnarkSetup {
        /// Circuit type: "groth16" (Poseidon-only) or "groth16-hybrid" (SHA-256 key hash + Poseidon MAC).
        #[arg(short, long, default_value = "groth16")]
        algorithm: String,

        /// Output file for the proving key (base64-encoded).
        #[arg(long, default_value = "snark-pk.b64")]
        proving_key: String,

        /// Output file for the verifying key (base64-encoded).
        #[arg(long, default_value = "snark-vk.b64")]
        verifying_key: String,
    },

    /// Sign a new token.
    Sign {
        /// Signing key file, or "-" for stdin.
        keyfile: String,

        /// Token validity duration (e.g. "4d", "1h", "30m").
        duration: String,

        /// Subject claim.
        #[arg(long)]
        subject: Option<String>,

        /// Audience claim.
        #[arg(long)]
        audience: Option<String>,

        /// Scope entries (repeatable, e.g. --scope read --scope write).
        #[arg(long)]
        scope: Vec<String>,

        /// Groth16 proving key file (required for groth16 algorithm).
        #[arg(long)]
        proving_key: Option<String>,
    },

    /// Verify a signed token against a key and current time.
    Verify {
        /// Key file (SigningKey for HMAC, VerifyingKey for asymmetric,
        /// SNARK verifying key for Groth16).
        /// Use "-" for stdin, but then token must be given explicitly.
        keyfile: String,

        /// Token (base64). If omitted, reads from stdin.
        token: Option<String>,

        /// Output as JSON instead of colored text.
        #[arg(long)]
        json: bool,
    },

    /// Inspect a token without verifying (no key needed).
    Inspect {
        /// Token (base64). If omitted, reads from stdin.
        token: Option<String>,

        /// Output as JSON instead of colored text.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::GenerateKey { algorithm } => cmd_generate_key(&algorithm),
        Command::GetVerifyingKey { keyfile } => cmd_get_verifying_key(&keyfile),
        Command::SnarkSetup {
            algorithm,
            proving_key,
            verifying_key,
        } => cmd_snark_setup(&algorithm, &proving_key, &verifying_key),
        Command::Sign {
            keyfile,
            duration,
            subject,
            audience,
            scope,
            proving_key,
        } => cmd_sign(&keyfile, &duration, subject, audience, scope, proving_key),
        Command::Verify {
            keyfile,
            token,
            json,
        } => cmd_verify(&keyfile, token, json),
        Command::Inspect { token, json } => cmd_inspect(token, json),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_generate_key(algorithm: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sk = match algorithm {
        "hmac" => {
            let secret_key = generate_hmac_key();
            ProtoSigningKey {
                algorithm: Algorithm::HmacSha256,
                secret_key: Zeroizing::new(secret_key),
                public_key: Vec::new(),
            }
        }
        "ed25519" => {
            let (seed, pk) = generate_ed25519_key()?;
            ProtoSigningKey {
                algorithm: Algorithm::Ed25519,
                secret_key: Zeroizing::new(seed),
                public_key: pk,
            }
        }
        "ml-dsa-44" => {
            let (sk_raw, pk) = generate_mldsa44_key()?;
            ProtoSigningKey {
                algorithm: Algorithm::MlDsa44,
                secret_key: Zeroizing::new(sk_raw),
                public_key: pk,
            }
        }
        "groth16" => {
            let secret_key = generate_hmac_key(); // same key format: random 32 bytes
            ProtoSigningKey {
                algorithm: Algorithm::Groth16Poseidon,
                secret_key: Zeroizing::new(secret_key),
                public_key: Vec::new(),
            }
        }
        "groth16-hybrid" => {
            let secret_key = generate_hmac_key();
            ProtoSigningKey {
                algorithm: Algorithm::Groth16Hybrid,
                secret_key: Zeroizing::new(secret_key),
                public_key: Vec::new(),
            }
        }
        _ => {
            return Err(format!(
                "unknown algorithm: {algorithm} (use 'hmac', 'ed25519', 'ml-dsa-44', 'groth16', or 'groth16-hybrid')"
            )
            .into())
        }
    };

    println!("{}", B64.encode(serialize_signing_key(&sk)));
    Ok(())
}

fn cmd_get_verifying_key(keyfile: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_keyfile(keyfile)?;
    let sk = deserialize_signing_key(&key_bytes)?;
    let vk = extract_verifying_key(&sk)?;
    println!("{}", B64.encode(serialize_verifying_key(&vk)));
    Ok(())
}

/// Maximum SNARK key input size. Proving keys can be tens of MB.
const MAX_SNARK_KEY_INPUT: u64 = 100_000_000; // 100 MB

fn cmd_snark_setup(
    algorithm: &str,
    pk_path: &str,
    vk_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (pk, vk) = match algorithm {
        "groth16" => {
            eprintln!("Running Groth16-Poseidon trusted setup...");
            snark::setup()?
        }
        "groth16-hybrid" => {
            eprintln!("Running Groth16-Hybrid trusted setup (this may take a minute)...");
            snark::setup_hybrid()?
        }
        _ => {
            return Err(format!(
                "unknown SNARK algorithm: {algorithm} (use 'groth16' or 'groth16-hybrid')"
            )
            .into())
        }
    };

    let pk_bytes = snark::serialize_proving_key(&pk)?;
    let vk_bytes = snark::serialize_verifying_key(&vk)?;

    std::fs::write(pk_path, B64.encode(&pk_bytes))?;
    std::fs::write(vk_path, B64.encode(&vk_bytes))?;

    eprintln!(
        "Proving key:   {} ({:.1} MB)",
        pk_path,
        pk_bytes.len() as f64 / 1_048_576.0
    );
    eprintln!(
        "Verifying key: {} ({:.1} KB)",
        vk_path,
        vk_bytes.len() as f64 / 1024.0
    );
    Ok(())
}

fn cmd_sign(
    keyfile: &str,
    duration_str: &str,
    subject: Option<String>,
    audience: Option<String>,
    scopes: Vec<String>,
    proving_key_file: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = read_keyfile(keyfile)?;
    let sk = deserialize_signing_key(&key_bytes)?;

    let duration: std::time::Duration = duration_str
        .parse::<humantime::Duration>()
        .map_err(|e| format!("invalid duration '{duration_str}': {e}"))?
        .into();

    if duration.as_secs() == 0 {
        return Err("duration must be at least 1 second".into());
    }

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
        Algorithm::Groth16Poseidon => {
            let pk_file = proving_key_file
                .ok_or("Groth16 signing requires --proving-key <file> (from snark-setup)")?;
            let pk_bytes = read_snark_keyfile(&pk_file)?;
            let pk = snark::deserialize_proving_key(&pk_bytes)?;
            let key: [u8; 32] = sk.secret_key.as_slice().try_into().map_err(|_| {
                format!("Groth16 key must be 32 bytes, got {}", sk.secret_key.len())
            })?;
            sign_groth16(&pk, &key, claims)?
        }
        Algorithm::Groth16Hybrid => {
            let pk_file = proving_key_file
                .ok_or("Groth16Hybrid signing requires --proving-key <file> (from snark-setup)")?;
            let pk_bytes = read_snark_keyfile(&pk_file)?;
            let pk = snark::deserialize_proving_key(&pk_bytes)?;
            let key: [u8; 32] = sk.secret_key.as_slice().try_into().map_err(|_| {
                format!(
                    "Groth16Hybrid key must be 32 bytes, got {}",
                    sk.secret_key.len()
                )
            })?;
            sign_groth16_hybrid(&pk, &key, claims)?
        }
    };

    println!("{}", B64.encode(&token_bytes));
    Ok(())
}

fn cmd_verify(
    keyfile: &str,
    token_arg: Option<String>,
    json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if keyfile == "-" && token_arg.is_none() {
        return Err("when keyfile is \"-\" (stdin), token must be provided as an argument".into());
    }

    let key_bytes = read_keyfile(keyfile)?;
    let token_bytes = read_token_input(token_arg)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is set before Unix epoch (1970-01-01)")?
        .as_secs();

    // Determine key type by trying each format:
    // 1. Proto VerifyingKey (Ed25519, ML-DSA-44)
    // 2. Proto SigningKey (HMAC)
    // 3. SNARK VerifyingKey (Groth16)
    let verified = if let Ok(vk) = deserialize_verifying_key(&key_bytes) {
        match vk.algorithm {
            Algorithm::Ed25519 => verify_ed25519(&vk.public_key, &token_bytes, now)?,
            Algorithm::MlDsa44 => verify_mldsa44(&vk.public_key, &token_bytes, now)?,
            Algorithm::HmacSha256 | Algorithm::Groth16Poseidon | Algorithm::Groth16Hybrid => {
                return Err("symmetric algorithm; use the signing key to verify".into());
            }
        }
    } else if let Ok(sk) = deserialize_signing_key(&key_bytes) {
        match sk.algorithm {
            Algorithm::HmacSha256 => verify_hmac(&sk.secret_key, &token_bytes, now)?,
            Algorithm::Groth16Poseidon | Algorithm::Groth16Hybrid => {
                return Err(
                    "use the SNARK verifying key (from snark-setup) to verify Groth16 tokens"
                        .into(),
                );
            }
            _ => {
                return Err(format!(
                    "expected an HMAC signing key or a verifying key, got {:?} signing key",
                    sk.algorithm
                )
                .into());
            }
        }
    } else if let Ok(snark_vk) = snark::deserialize_verifying_key(&key_bytes) {
        // Peek at the token's algorithm to dispatch to the correct verifier.
        let token = deserialize_signed_token(&token_bytes)?;
        let payload = deserialize_payload(&token.payload_bytes)?;
        match payload.metadata.algorithm {
            Algorithm::Groth16Poseidon => verify_groth16(&snark_vk, &token_bytes, now)?,
            Algorithm::Groth16Hybrid => verify_groth16_hybrid(&snark_vk, &token_bytes, now)?,
            other => {
                return Err(format!(
                    "SNARK verifying key given but token algorithm is {:?} (expected Groth16Poseidon or Groth16Hybrid)",
                    other
                ).into());
            }
        }
    } else {
        return Err(
            "could not parse key file as VerifyingKey, SigningKey, or SNARK VerifyingKey".into(),
        );
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&verified)?);
    } else {
        let payload = Payload {
            metadata: verified.metadata.clone(),
            claims: verified.claims.clone(),
        };
        println!("{}", "OK".green().bold());
        print_payload_colored(&payload);
    }
    Ok(())
}

fn cmd_inspect(token_arg: Option<String>, json: bool) -> Result<(), Box<dyn std::error::Error>> {
    let token_bytes = read_token_input(token_arg)?;

    match deserialize_signed_token(&token_bytes) {
        Ok(token) => {
            let payload = deserialize_payload(&token.payload_bytes)?;
            if json {
                let mut output = serde_json::json!({
                    "type": "SignedToken",
                    "payload": payload,
                    "signature_base64": B64.encode(&token.signature),
                    "total_bytes": token_bytes.len(),
                });
                if !token.proof.is_empty() {
                    if let Some(obj) = output.as_object_mut() {
                        obj.insert(
                            "proof_base64".into(),
                            serde_json::Value::String(B64.encode(&token.proof)),
                        );
                    }
                }
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                print_payload_colored(&payload);
                print_field("Signature", &B64.encode(&token.signature).magenta());
                if !token.proof.is_empty() {
                    print_field("Proof", &B64.encode(&token.proof).magenta());
                }
                print_field("Size", &format_size(token_bytes.len()).cyan());
            }
        }
        Err(_) => match deserialize_payload(&token_bytes) {
            Ok(payload) => {
                if json {
                    let output = serde_json::json!({
                        "type": "Payload",
                        "payload": payload,
                        "total_bytes": token_bytes.len(),
                    });
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    print_payload_colored(&payload);
                    print_field("Size", &format_size(token_bytes.len()).cyan());
                }
            }
            Err(e) => {
                return Err(format!("could not parse as SignedToken or Payload: {e}").into());
            }
        },
    }

    Ok(())
}

// --- Display helpers ---

fn print_field(label: &str, value: &dyn std::fmt::Display) {
    println!("  {:>12}  {}", label.bold(), value);
}

fn print_payload_colored(payload: &Payload) {
    let algo_name = match payload.metadata.algorithm {
        Algorithm::HmacSha256 => "HMAC-SHA256",
        Algorithm::Ed25519 => "Ed25519",
        Algorithm::MlDsa44 => "ML-DSA-44",
        Algorithm::Groth16Poseidon => "Groth16-Poseidon",
        Algorithm::Groth16Hybrid => "Groth16-Hybrid",
    };
    print_field("Algorithm", &algo_name.green());

    let key_id_str = match &payload.metadata.key_identifier {
        KeyIdentifier::KeyHash(h) => format!("{} (key_hash)", B64.encode(h)),
        KeyIdentifier::PublicKey(pk) => {
            if pk.len() <= 32 {
                format!("{} (public_key)", B64.encode(pk))
            } else {
                format!(
                    "{}... (public_key, {} B)",
                    B64.encode(pk.get(..24).unwrap_or(pk)),
                    pk.len()
                )
            }
        }
        KeyIdentifier::FullKeyHash(h) => format!("{} (full_key_hash)", B64.encode(h)),
    };
    print_field("Key ID", &key_id_str.magenta());

    print_field(
        "Expires",
        &format_timestamp(payload.claims.expires_at).cyan(),
    );
    if payload.claims.not_before != 0 {
        print_field(
            "Not Before",
            &format_timestamp(payload.claims.not_before).cyan(),
        );
    }
    if payload.claims.issued_at != 0 {
        print_field(
            "Issued At",
            &format_timestamp(payload.claims.issued_at).cyan(),
        );
    }
    if !payload.claims.subject.is_empty() {
        print_field("Subject", &payload.claims.subject.green());
    }
    if !payload.claims.audience.is_empty() {
        print_field("Audience", &payload.claims.audience.green());
    }
    if !payload.claims.scopes.is_empty() {
        print_field("Scopes", &payload.claims.scopes.join(", ").green());
    }
}

fn format_timestamp(unix_secs: u64) -> String {
    match UNIX_EPOCH.checked_add(std::time::Duration::from_secs(unix_secs)) {
        Some(d) => humantime::format_rfc3339_seconds(d).to_string(),
        None => format!("{unix_secs} (epoch seconds)"),
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{} B ({:.1} KB)", bytes, bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

// --- I/O helpers ---

/// Maximum key input size (base64-encoded). ML-DSA-44 SigningKey is ~5.2 KB base64.
const MAX_KEY_INPUT: u64 = 100_000;

/// Read a key from a file path or "-" for stdin. Decodes base64.
/// The intermediate base64 string is zeroized on drop to avoid leaving
/// key material in memory.
fn read_keyfile(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let raw: Zeroizing<String> = if path == "-" {
        let mut buf = String::new();
        io::stdin()
            .take(MAX_KEY_INPUT + 1)
            .read_to_string(&mut buf)?;
        if buf.len() as u64 > MAX_KEY_INPUT {
            return Err(format!("key input too large (max {} bytes)", MAX_KEY_INPUT).into());
        }
        Zeroizing::new(buf)
    } else {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > MAX_KEY_INPUT {
            return Err(format!(
                "key file too large: {} bytes (max {})",
                metadata.len(),
                MAX_KEY_INPUT
            )
            .into());
        }
        Zeroizing::new(std::fs::read_to_string(path)?)
    };
    decode_base64(raw.trim())
}

/// Maximum token input size (base64-encoded). 16 KB covers even ML-DSA-44 tokens with headroom.
const MAX_TOKEN_INPUT: u64 = 16_384;

/// Read token bytes from an explicit argument or stdin, decoding base64.
fn read_token_input(token_arg: Option<String>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let input = match token_arg {
        Some(s) => s,
        None => {
            let mut buf = String::new();
            io::stdin()
                .take(MAX_TOKEN_INPUT + 1)
                .read_to_string(&mut buf)?;
            if buf.len() as u64 > MAX_TOKEN_INPUT {
                return Err(
                    format!("token input too large (max {} bytes)", MAX_TOKEN_INPUT).into(),
                );
            }
            buf
        }
    };
    decode_base64(input.trim())
}

/// Read a SNARK key file (proving or verifying key). These can be large (~tens of MB).
fn read_snark_keyfile(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_SNARK_KEY_INPUT {
        return Err(format!(
            "SNARK key file too large: {} bytes (max {})",
            metadata.len(),
            MAX_SNARK_KEY_INPUT
        )
        .into());
    }
    let raw = std::fs::read_to_string(path)?;
    decode_base64(raw.trim())
}

/// Decode a base64 string (URL-safe no-pad or standard).
fn decode_base64(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Ok(bytes) = B64.decode(input) {
        return Ok(bytes);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(input) {
        return Ok(bytes);
    }
    Err("could not decode base64".into())
}
