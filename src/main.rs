use std::error::Error;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, Read as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::Engine as _;
use clap::builder::styling::{AnsiColor, Effects, Styles};
use clap::{Parser, Subcommand};
use colored::Colorize as _;

use protoken::serialize::{deserialize_claims, deserialize_signed_token, MAX_SIGNED_TOKEN_BYTES};
use protoken::{Algorithm, Claims, KeyIdentifier, SigningKey, VerifyingKey, Zeroizing};

type CliResult = Result<(), Box<dyn Error>>;

/// Output encoding: URL-safe base64 without padding.
const B64: GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Input decoding accepts either alphabet, padded or not, so keys and tokens
/// produced by other tools (for example Python's `base64.urlsafe_b64encode`,
/// which pads) are accepted as well as our own output.
const ACCEPT_PADDING: GeneralPurposeConfig =
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
const B64_URL_SAFE_IN: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, ACCEPT_PADDING);
const B64_STANDARD_IN: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, ACCEPT_PADDING);

/// The largest key, an FN-DSA-1024 SigningKey, is ~5.6 KB of base64.
const MAX_KEY_INPUT: usize = 16_384;
/// Base64 expands by 4/3; the rest leaves room for surrounding whitespace.
const MAX_TOKEN_INPUT: usize = MAX_SIGNED_TOKEN_BYTES * 3 / 2;

const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default())
    .placeholder(AnsiColor::Cyan.on_default())
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .valid(AnsiColor::Green.on_default());

#[derive(Parser)]
#[command(
    name = "protoken",
    about = "Protobuf-based signed tokens",
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
        /// hmac-sha384 (or hmac), ml-dsa-{44,65,87}, slh-dsa-sha2-{128s,192s,256s},
        /// or fn-dsa-{512,1024} (experimental).
        #[arg(short, long, default_value_t = Algorithm::MlDsa44)]
        algorithm: Algorithm,
    },

    /// Get the verifying key from a signing key.
    GetVerifyingKey {
        /// Signing key file, or "-" for stdin.
        keyfile: String,
    },

    /// Sign a new token.
    Sign {
        /// Signing key file, or "-" for stdin.
        keyfile: String,

        /// Token validity duration (e.g. "4d", "1h", "30m").
        duration: humantime::Duration,

        /// Subject claim.
        #[arg(long, default_value_t)]
        subject: String,

        /// Audience claim.
        #[arg(long, default_value_t)]
        audience: String,

        /// Scope entries (repeatable, e.g. --scope read --scope write).
        #[arg(long)]
        scope: Vec<String>,
    },

    /// Verify a signed token against a key and the current time.
    Verify {
        /// Key file (SigningKey for HMAC, VerifyingKey for asymmetric).
        /// Use "-" for stdin, but then the token must be given explicitly.
        keyfile: String,

        /// Token (base64). If omitted, reads from stdin.
        token: Option<String>,

        /// Output as JSON instead of colored text.
        #[arg(long)]
        json: bool,
    },

    /// Inspect a token without verifying it (no key needed).
    Inspect {
        /// Token (base64). If omitted, reads from stdin.
        token: Option<String>,

        /// Output as JSON instead of colored text.
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let result = match Cli::parse().command {
        Command::GenerateKey { algorithm } => cmd_generate_key(algorithm),
        Command::GetVerifyingKey { keyfile } => cmd_get_verifying_key(&keyfile),
        Command::Sign {
            keyfile,
            duration,
            subject,
            audience,
            scope,
        } => cmd_sign(&keyfile, duration.into(), subject, audience, scope),
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

fn cmd_generate_key(algorithm: Algorithm) -> CliResult {
    let key = SigningKey::generate(algorithm)?;
    println!("{}", *Zeroizing::new(B64.encode(key.to_bytes())));
    Ok(())
}

fn cmd_get_verifying_key(keyfile: &str) -> CliResult {
    let key = read_signing_key(keyfile)?;
    println!("{}", B64.encode(key.verifying_key()?.to_bytes()));
    Ok(())
}

fn cmd_sign(
    keyfile: &str,
    duration: Duration,
    subject: String,
    audience: String,
    scopes: Vec<String>,
) -> CliResult {
    let key = read_signing_key(keyfile)?;

    if duration.as_secs() == 0 {
        return Err("duration must be at least 1 second".into());
    }
    let now = current_unix_time()?;
    let expires_at = now
        .checked_add(duration.as_secs())
        .ok_or("duration overflow")?;

    let claims = Claims {
        expires_at,
        not_before: now,
        issued_at: now,
        subject,
        audience,
        scopes,
    };

    println!("{}", B64.encode(key.sign(&claims)?));
    Ok(())
}

fn cmd_verify(keyfile: &str, token_arg: Option<String>, json: bool) -> CliResult {
    if keyfile == "-" && token_arg.is_none() {
        return Err("when keyfile is \"-\" (stdin), the token must be given as an argument".into());
    }

    let key_bytes = read_key_bytes(keyfile)?;
    let token_bytes = read_token_input(token_arg)?;
    let now = current_unix_time()?;

    // A key file is either a VerifyingKey (asymmetric) or an HMAC SigningKey.
    // Asymmetric signing keys are refused so secrets are not passed around
    // where only the public half is needed.
    let verified = match VerifyingKey::from_bytes(&key_bytes) {
        Ok(vk) => vk.verify(&token_bytes, now)?,
        Err(vk_err) => match SigningKey::from_bytes(&key_bytes) {
            Ok(sk) if sk.algorithm().is_symmetric() => sk.verify(&token_bytes, now)?,
            Ok(sk) => {
                return Err(format!(
                    "{} signing key given; verify with its verifying key (see get-verifying-key)",
                    sk.algorithm()
                )
                .into())
            }
            Err(sk_err) => {
                return Err(
                    format!("not a VerifyingKey ({vk_err}) or a SigningKey ({sk_err})").into(),
                )
            }
        },
    };

    if json {
        println!("{}", ascii_json(&verified)?);
    } else {
        println!("{}", "OK".green().bold());
        print_token(
            verified.algorithm,
            &verified.key_identifier,
            &verified.claims,
        );
    }
    Ok(())
}

fn cmd_inspect(token_arg: Option<String>, json: bool) -> CliResult {
    let bytes = read_token_input(token_arg)?;

    let token = match deserialize_signed_token(&bytes) {
        Ok(token) => token,
        // Not an envelope; it may be bare Claims bytes.
        Err(token_err) => {
            let claims = deserialize_claims(&bytes)
                .map_err(|_| format!("could not parse as SignedToken ({token_err}) or Claims"))?;
            if json {
                let output = serde_json::json!({
                    "type": "Claims",
                    "claims": claims,
                    "total_bytes": bytes.len(),
                });
                println!("{}", ascii_json(&output)?);
            } else {
                print_claims(&claims);
                print_field("Size", &format_size(bytes.len()).cyan());
            }
            return Ok(());
        }
    };

    let claims = deserialize_claims(&token.payload)
        .map_err(|e| format!("could not parse token payload as Claims: {e}"))?;

    if json {
        let output = serde_json::json!({
            "type": "SignedToken",
            "algorithm": token.algorithm,
            "key_identifier": token.key_identifier,
            "claims": claims,
            "signature_base64": B64.encode(&token.signature),
            "total_bytes": bytes.len(),
        });
        println!("{}", ascii_json(&output)?);
    } else {
        print_token(token.algorithm, &token.key_identifier, &claims);
        print_field("Signature", &abbreviate(&token.signature).magenta());
        print_field("Size", &format_size(bytes.len()).cyan());
    }
    Ok(())
}

// --- Display helpers ---

/// Pretty JSON with everything outside printable ASCII escaped. serde_json
/// leaves DEL, C1 controls, and bidirectional overrides in strings as they are.
fn ascii_json(value: &impl serde::Serialize) -> Result<String, Box<dyn Error>> {
    let mut out = String::new();
    for unit in serde_json::to_string_pretty(value)?.encode_utf16() {
        match u8::try_from(unit) {
            Ok(byte) if byte < 0x7F => out.push(byte.into()),
            _ => write!(out, "\\u{unit:04x}")?,
        }
    }
    Ok(out)
}

fn print_field(label: &str, value: &dyn std::fmt::Display) {
    println!("  {:>12}  {value}", label.bold());
}

fn print_token(algorithm: Algorithm, key_identifier: &KeyIdentifier, claims: &Claims) {
    print_field("Algorithm", &algorithm.to_string().green());
    print_field("Key ID", &format_key_identifier(key_identifier).magenta());
    print_claims(claims);
}

fn format_key_identifier(key_identifier: &KeyIdentifier) -> String {
    let bytes = abbreviate(key_identifier.as_bytes());
    format!("{bytes} ({})", key_identifier.type_name())
}

/// Base64, cut short for long values; `--json` shows them in full.
fn abbreviate(bytes: &[u8]) -> String {
    const ABBREVIATE_OVER: usize = 64;
    const SHOWN_BYTES: usize = 24;
    match bytes.get(..SHOWN_BYTES) {
        Some(prefix) if bytes.len() > ABBREVIATE_OVER => {
            format!("{}... [{} B]", B64.encode(prefix), bytes.len())
        }
        _ => B64.encode(bytes),
    }
}

/// Claim strings are untrusted, so they are printed quoted and escaped to
/// keep control sequences away from the terminal.
fn print_claims(claims: &Claims) {
    // Only `inspect` can reach a payload without expires_at; verified tokens always have one.
    if claims.expires_at == 0 {
        print_field("Expires", &"(not set; token can never verify)".red());
    } else {
        print_field("Expires", &format_timestamp(claims.expires_at).cyan());
    }
    if claims.not_before != 0 {
        print_field("Not Before", &format_timestamp(claims.not_before).cyan());
    }
    if claims.issued_at != 0 {
        print_field("Issued At", &format_timestamp(claims.issued_at).cyan());
    }
    if !claims.subject.is_empty() {
        print_field("Subject", &format!("{:?}", claims.subject).green());
    }
    if !claims.audience.is_empty() {
        print_field("Audience", &format!("{:?}", claims.audience).green());
    }
    if !claims.scopes.is_empty() {
        print_field("Scopes", &format!("{:?}", claims.scopes).green());
    }
}

/// RFC 3339 if representable. humantime's formatter reports an error (which
/// `to_string` would turn into a panic) for years beyond 9999, and SystemTime
/// itself can overflow, so both cases fall back to the raw number. Timestamps
/// come from untrusted tokens, so this must not panic.
fn format_timestamp(unix_secs: u64) -> String {
    let mut out = String::new();
    let formatted = UNIX_EPOCH
        .checked_add(Duration::from_secs(unix_secs))
        .is_some_and(|time| write!(out, "{}", humantime::format_rfc3339_seconds(time)).is_ok());
    if formatted {
        out
    } else {
        format!("{unix_secs} (epoch seconds)")
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 {
        format!("{bytes} B ({:.1} KB)", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

// --- I/O helpers ---

fn current_unix_time() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is set before the Unix epoch")?
        .as_secs())
}

/// Read at most `max_len` bytes of text from `reader`, failing if there is
/// more. The buffer is allocated once at full size: growing it incrementally
/// would leave un-zeroized copies of a partially read secret behind.
fn read_bounded(
    reader: impl io::Read,
    max_len: usize,
    what: &str,
) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let limit = max_len + 1;
    let mut buf = Zeroizing::new(String::with_capacity(limit));
    reader.take(limit as u64).read_to_string(&mut buf)?;
    if buf.len() > max_len {
        return Err(format!("{what} input too large (max {max_len} bytes)").into());
    }
    Ok(buf)
}

/// Read and base64-decode a file, or stdin when `path` is "-". Both the text
/// and the decoded bytes are zeroized on drop since they may hold a secret.
fn read_encoded_input(
    path: &str,
    max_len: usize,
    what: &str,
) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let text = if path == "-" {
        read_bounded(io::stdin().lock(), max_len, what)?
    } else {
        let file = File::open(path).map_err(|e| format!("cannot open {what} file {path}: {e}"))?;
        read_bounded(file, max_len, what)?
    };
    decode_base64(text.trim())
}

fn read_key_bytes(path: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    read_encoded_input(path, MAX_KEY_INPUT, "key")
}

fn read_signing_key(path: &str) -> Result<SigningKey, Box<dyn Error>> {
    Ok(SigningKey::from_bytes(&read_key_bytes(path)?)?)
}

/// Token bytes from the argument if given, otherwise from stdin.
fn read_token_input(token_arg: Option<String>) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    match token_arg {
        Some(text) => decode_base64(text.trim()),
        None => read_encoded_input("-", MAX_TOKEN_INPUT, "token"),
    }
}

/// Decode base64 in either alphabet, with or without padding. The alphabet is
/// chosen up front and the buffer is zeroized even if decoding fails partway.
fn decode_base64(input: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn Error>> {
    let engine = if input.contains(['+', '/']) {
        B64_STANDARD_IN
    } else {
        B64_URL_SAFE_IN
    };
    let mut decoded = Zeroizing::new(Vec::new());
    engine
        .decode_vec(input, &mut decoded)
        .map_err(|e| format!("could not decode base64: {e}"))?;
    Ok(decoded)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_handles_representable_and_huge_values() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_timestamp(1_700_000_000), "2023-11-14T22:13:20Z");
        // 9999-12-31T23:59:59Z is the last second humantime can format.
        assert_eq!(format_timestamp(253_402_300_799), "9999-12-31T23:59:59Z");
        assert_eq!(
            format_timestamp(253_402_300_800),
            "253402300800 (epoch seconds)"
        );
        assert_eq!(
            format_timestamp(u64::MAX),
            format!("{} (epoch seconds)", u64::MAX)
        );
    }

    #[test]
    fn decode_base64_accepts_every_common_encoding() {
        // Bytes chosen so that the alphabets differ ('-'/'_' vs '+'/'/') and
        // the encoding needs padding.
        let raw: Vec<u8> = vec![0xfb, 0xff, 0xbf, 0x01, 0x02];
        let encodings = [
            B64.encode(&raw),
            base64::engine::general_purpose::URL_SAFE.encode(&raw),
            base64::engine::general_purpose::STANDARD.encode(&raw),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(&raw),
        ];
        assert!(encodings.iter().any(|e| e.contains('-') || e.contains('_')));
        assert!(encodings.iter().any(|e| e.ends_with('=')));
        for encoding in &encodings {
            assert_eq!(*decode_base64(encoding).unwrap(), raw, "{encoding}");
        }
        assert!(decode_base64("not base64!").is_err());
        // Mixing the alphabets is still rejected.
        assert!(decode_base64("-/").is_err());
    }

    #[test]
    fn read_bounded_enforces_the_limit_without_reading_past_it() {
        let text = read_bounded("abc".as_bytes(), 3, "test").unwrap();
        assert_eq!(*text, "abc");
        let err = read_bounded("abcd".as_bytes(), 3, "test").unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");
        // A stream far larger than the limit is not read in full.
        assert!(read_bounded(io::repeat(b'x'), 16, "test").is_err());
    }

    #[test]
    fn format_key_identifier_abbreviates_only_long_public_keys() {
        let hash = KeyIdentifier::KeyHash([1; 8]);
        assert_eq!(format_key_identifier(&hash), "AQEBAQEBAQE (key_hash)");

        let slh_dsa = KeyIdentifier::PublicKey(vec![0; 64]);
        assert_eq!(
            format_key_identifier(&slh_dsa),
            format!("{} (public_key)", "A".repeat(86))
        );

        let ml_dsa = KeyIdentifier::PublicKey(vec![0; 1312]);
        assert_eq!(
            format_key_identifier(&ml_dsa),
            format!("{}... [1312 B] (public_key)", "A".repeat(32))
        );
    }

    #[test]
    fn ascii_json_escapes_terminal_controls_and_roundtrips() {
        let text = "a\u{1b}\u{7f}\u{9b}\u{202e}é𝄞~";
        let json = ascii_json(&text).unwrap();
        assert_eq!(json, r#""a\u001b\u007f\u009b\u202e\u00e9\ud834\udd1e~""#);
        assert_eq!(serde_json::from_str::<String>(&json).unwrap(), text);
    }

    #[test]
    fn format_size_switches_to_kilobytes() {
        assert_eq!(format_size(56), "56 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(2457), "2457 B (2.4 KB)");
    }
}
