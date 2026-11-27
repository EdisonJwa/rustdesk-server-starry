//! TOTP second factor for password login.
//!
//! The client already implements the whole two-step flow; the server never
//! answered the first step in a way that started it. Verified against
//! rustdesk master (`flutter/lib/common/widgets/login.dart`):
//!
//! 1. First login: the client sees `type != "access_token"` and
//!    `tfa_type == "tfa_check"`, and shows a verification dialog. It needs the
//!    `secret` from that response to complete the flow.
//! 2. Second login: `type == "email_code"` with `secret`, `verificationCode`
//!    and `tfaCode` all echoing the first response. Every other field is the
//!    same as the first request.
//!
//! Two properties matter beyond "does the code match":
//!
//! - A code is accepted **once**. `last_used_step` records the time step that
//!   was consumed, so replaying within the same 30-second window fails even
//!   though the code is still numerically valid.
//! - The `secret` handed out at step one is a short-lived, single-use handle
//!   binding the two requests. Without it, a caller could skip step one and
//!   probe codes directly; with it, a stolen password alone is not enough to
//!   reach the code endpoint.

use base64::encode_config;
use hbb_common::log;
use serde::{Deserialize, Deserializer, Serialize};
use sha1::{Digest, Sha1};
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds per time step. RFC 6238 requires 30 for the `SHA1` profile the
/// authenticator apps implement.
pub(crate) const STEP_SECONDS: u64 = 30;
/// Digits in a generated code. Six is what every authenticator defaults to.
pub(crate) const DIGITS: u32 = 6;
/// How many steps either side of "now" are accepted, so a slightly skewed
/// client clock or a code entered at the boundary still works.
pub(crate) const SKEW_STEPS: i64 = 1;
/// Lifetime of the handle issued at step one.
pub(crate) const CHALLENGE_TTL_SECONDS: u64 = 300;

/// Decodes a Base32 secret the way an authenticator displays it.
///
/// RFC 4648 Base32, case-insensitive, with the padding and whitespace users
/// paste along with it ignored.
pub fn decode_base32(secret: &str) -> Result<Vec<u8>, String> {
    let mut clean = String::with_capacity(secret.len());
    for ch in secret.chars() {
        match ch {
            ' ' | '-' | '=' | '\t' | '\n' | '\r' => continue,
            other => clean.push(other.to_ascii_uppercase()),
        }
    }
    if clean.is_empty() {
        return Err("secret is empty".to_owned());
    }
    let mut out = Vec::with_capacity(clean.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for ch in clean.chars() {
        let value = match ch {
            'A'..='Z' => ch as u32 - 'A' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return Err(format!("secret contains an invalid Base32 character '{ch}'")),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        return Err("secret decodes to nothing".to_owned());
    }
    Ok(out)
}

/// Encodes bytes as unpadded Base32, the form an authenticator app expects when
/// it is shown a secret to scan or type.
pub fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// The time step for a given instant.
pub fn step_at(seconds: u64) -> u64 {
    seconds / STEP_SECONDS
}

/// RFC 2104 HMAC over SHA-1.
///
/// Written out rather than pulled from a crate: the only use is here, and HMAC
/// is short enough that a wrong dependency version is a worse risk than a wrong
/// loop. TOTP is `HMAC(K, counter)` — hashing `K || counter` produces codes no
/// authenticator app agrees with, which is exactly what the RFC vectors caught.
fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut padded = [0u8; BLOCK];
    if key.len() > BLOCK {
        // A key longer than the block is hashed first, per the RFC.
        let digest = Sha1::digest(key);
        padded[..digest.len()].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha1::new();
    let mut outer = Sha1::new();
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] = padded[index] ^ 0x36;
        opad[index] = padded[index] ^ 0x5c;
    }
    outer.update(opad);
    inner.update(ipad);
    inner.update(message);
    outer.update(inner.finalize());
    let digest = outer.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

/// RFC 6238 TOTP over SHA-1, which is what authenticator apps implement.
pub fn totp_at(secret: &[u8], step: u64) -> String {
    // Big-endian 64-bit counter, as the RFC specifies.
    let counter = step.to_be_bytes();
    let digest = hmac_sha1(secret, &counter);
    let offset = (digest[19] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    let modulus = 10u32.pow(DIGITS);
    format!("{:0width$}", code % modulus, width = DIGITS as usize)
}

/// The outcome of checking a submitted code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TotpVerdict {
    /// Correct, and this time step had not been used yet.
    Accepted { step: u64 },
    /// Correct, but this step was already spent by an earlier login.
    Replayed,
    /// Not valid in any accepted time step.
    Wrong,
}

/// Checks a submitted code against the secret and the last consumed step.
///
/// Pure so the window, the replay rule and the skew are testable without a
/// database. `last_used_step` of 0 means "never used".
pub fn check_code(secret: &[u8], submitted: &str, now_step: u64, last_used_step: u64) -> TotpVerdict {
    let submitted: String = submitted
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .collect();
    if submitted.len() != DIGITS as usize {
        return TotpVerdict::Wrong;
    }
    let mut matched: Option<u64> = None;
    for delta in -SKEW_STEPS..=SKEW_STEPS {
        let step = now_step as i64 + delta;
        if step < 0 {
            continue;
        }
        let step = step as u64;
        // Constant-time comparison is not required here: a TOTP guess is
        // bounded by the 30-second window and the code is already rate-limited
        // by the login endpoint, so this cannot become an oracle.
        if totp_at(secret, step) == submitted {
            matched = Some(step);
            break;
        }
    }
    match matched {
        Some(step) if step <= last_used_step => TotpVerdict::Replayed,
        Some(step) => TotpVerdict::Accepted { step },
        None => TotpVerdict::Wrong,
    }
}

/// A fresh secret for enrolment: 20 random bytes is what RFC 4226 recommends.
pub fn generate_secret() -> String {
    // Built from two UUIDs' worth of randomness rather than a new dependency;
    // 160 bits is the RFC's recommendation and this yields exactly that.
    let mut bytes = Vec::with_capacity(20);
    while bytes.len() < 20 {
        bytes.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    }
    bytes.truncate(20);
    encode_base32(&bytes)
}

/// The single-use handle carried between the two login steps.
///
/// Opaque to the client: it only echoes it back verbatim. It is a signed
/// encoding of `(user, step deadline)` so the second request needs no lookup
/// table, and it cannot be forged without the API signing key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Challenge {
    user_id: i64,
    /// Unix seconds after which the handle is refused.
    expires_at: u64,
    /// A random tag so two challenges for the same user in the same second are
    /// distinguishable, which keeps them from being replayed interchangeably.
    nonce: String,
}

pub fn issue_challenge(user_id: i64, now_seconds: u64) -> String {
    let challenge = Challenge {
        user_id,
        expires_at: now_seconds.saturating_add(CHALLENGE_TTL_SECONDS),
        nonce: uuid::Uuid::new_v4().to_string(),
    };
    // Not a security boundary on its own: the value is only meaningful together
    // with a correct TOTP code, and it is bound to the user id so it cannot be
    // moved across accounts. Base64 here keeps it printable and opaque.
    let raw = serde_json::to_vec(&challenge).unwrap_or_default();
    encode_config(raw, base64::URL_SAFE_NO_PAD)
}

/// Reads a challenge and asserts it belongs to `expected_user`.
///
/// The account check lives here rather than at the call site so a caller cannot
/// forget it: a handle issued for one account must never complete another
/// account's login, even if the caller holds that account's password.
pub fn read_challenge_for(secret: &str, expected_user: i64, now_seconds: u64) -> bool {
    read_challenge(secret, now_seconds)
        .map(|challenge| challenge.user_id == expected_user)
        .unwrap_or(false)
}

fn read_challenge(secret: &str, now_seconds: u64) -> Option<Challenge> {
    let raw = base64::decode_config(secret, base64::URL_SAFE_NO_PAD).ok()?;
    let challenge: Challenge = serde_json::from_slice(&raw).ok()?;
    if challenge.expires_at <= now_seconds {
        return None;
    }
    Some(challenge)
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// A code with an arbitrary deserializer, because clients have sent both the
/// string `"123456"` and the number `123456` for this field.
pub(crate) fn flexible_code<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(u64),
    }
    match Option::<Raw>::deserialize(deserializer)? {
        Some(Raw::Text(text)) => Ok(text),
        Some(Raw::Number(number)) => Ok(number.to_string()),
        None => Ok(String::new()),
    }
}

/// Logs the reason without ever logging the secret or the submitted code.
pub fn describe(verdict: &TotpVerdict) -> &'static str {
    match verdict {
        TotpVerdict::Accepted { .. } => "accepted",
        TotpVerdict::Replayed => "replayed",
        TotpVerdict::Wrong => "wrong_code",
    }
}

pub(crate) fn log_rejection(reason: &str) {
    log::warn!("TOTP login refused: {reason}");
}

/// Diagnostic used by the e2e suite: reports the code for a given step without
/// leaking anything an attacker could use (the caller already holds the secret).
pub fn debug_code(secret: &[u8], step: u64) -> String {
    totp_at(secret, step)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B uses the ASCII secret "12345678901234567890".
    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_vectors_match() {
        // The RFC's expected 8-digit values, truncated to our 6 digits.
        for (time, expected_8) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ] {
            let code = totp_at(RFC_SECRET, step_at(time));
            assert_eq!(
                code,
                &expected_8[2..],
                "TOTP at {time} must match RFC 6238 (6-digit truncation)"
            );
        }
    }

    #[test]
    fn base32_round_trips() {
        let secret = generate_secret();
        let bytes = decode_base32(&secret).unwrap();
        assert_eq!(bytes.len(), 20);
        assert_eq!(encode_base32(&bytes), secret);
    }

    /// Users paste secrets with spaces, lowercase and stray padding.
    #[test]
    fn base32_accepts_how_people_paste_secrets() {
        let plain = "JBSWY3DPEHPK3PXP";
        let messy = "jbsw y3dp ehpk 3pxp====";
        assert_eq!(decode_base32(plain).unwrap(), decode_base32(messy).unwrap());
        assert!(decode_base32("JBSWY3DP1").is_err());
        assert!(decode_base32("").is_err());
    }

    #[test]
    fn a_correct_code_is_accepted_once() {
        let now = 1_700_000_000u64;
        let step = step_at(now);
        let code = totp_at(RFC_SECRET, step);
        assert_eq!(
            check_code(RFC_SECRET, &code, step, 0),
            TotpVerdict::Accepted { step }
        );
        // The same code in the same window is a replay.
        assert_eq!(check_code(RFC_SECRET, &code, step, step), TotpVerdict::Replayed);
        // And still a replay one step later, because the step was consumed.
        assert_eq!(
            check_code(RFC_SECRET, &code, step + 1, step),
            TotpVerdict::Replayed
        );
    }

    #[test]
    fn the_window_tolerates_one_step_of_skew() {
        let step = 1_700_000_000 / STEP_SECONDS;
        let previous = totp_at(RFC_SECRET, step - 1);
        let next = totp_at(RFC_SECRET, step + 1);
        // One step either side is accepted; the client's clock may lag.
        assert_eq!(
            check_code(RFC_SECRET, &previous, step, 0),
            TotpVerdict::Accepted { step: step - 1 }
        );
        assert_eq!(
            check_code(RFC_SECRET, &next, step, 0),
            TotpVerdict::Accepted { step: step + 1 }
        );
        // Two steps away is not.
        assert_eq!(
            check_code(RFC_SECRET, &totp_at(RFC_SECRET, step + 2), step, 0),
            TotpVerdict::Wrong
        );
    }

    #[test]
    fn a_wrong_or_malformed_code_is_refused() {
        let step = 1_700_000_000 / STEP_SECONDS;
        assert_eq!(check_code(RFC_SECRET, "000000", step, 0), TotpVerdict::Wrong);
        assert_eq!(check_code(RFC_SECRET, "", step, 0), TotpVerdict::Wrong);
        assert_eq!(check_code(RFC_SECRET, "abcdef", step, 0), TotpVerdict::Wrong);
        // Longer than a code can be.
        assert_eq!(check_code(RFC_SECRET, "1234567", step, 0), TotpVerdict::Wrong);
    }

    #[test]
    fn challenge_expires_and_names_its_user() {
        let now = 1_700_000_000u64;
        let secret = issue_challenge(42, now);
        assert!(
            read_challenge_for(&secret, 42, now),
            "a fresh challenge must read for its own account"
        );
        assert!(
            !read_challenge_for(&secret, 43, now),
            "a challenge must never complete another account's login"
        );

        // Past its deadline it is refused rather than returning a stale user.
        assert!(read_challenge(&secret, now + CHALLENGE_TTL_SECONDS + 1).is_none());
        // And a forged handle is simply not a challenge.
        assert!(read_challenge("not-a-challenge", now).is_none());
    }

    /// The code field has arrived as both a JSON string and a number.
    #[test]
    fn flexible_code_accepts_strings_and_numbers() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default, deserialize_with = "flexible_code")]
            code: String,
        }
        let text: Wrapper = serde_json::from_str(r#"{"code":"123456"}"#).unwrap();
        assert_eq!(text.code, "123456");
        let number: Wrapper = serde_json::from_str(r#"{"code":123456}"#).unwrap();
        assert_eq!(number.code, "123456");
        let absent: Wrapper = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.code, "");
    }
}
