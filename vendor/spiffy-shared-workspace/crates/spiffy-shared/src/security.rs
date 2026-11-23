use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IpcAuthToken(String);

impl IpcAuthToken {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Self(encoded)
    }

    pub fn from_encoded(value: String) -> Result<Self, &'static str> {
        let decoded = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| "IPC token is not valid base64url")?;
        if decoded.len() != 32 {
            return Err("IPC token must contain exactly 256 bits");
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, candidate: &str) -> bool {
        self.0.as_bytes().ct_eq(candidate.as_bytes()).into()
    }
}

#[derive(Debug, Clone, Default)]
pub struct SensitiveClipboardInput<'a> {
    pub content: &'a str,
    pub source_application: Option<&'a str>,
    pub concealed_marker: bool,
    pub transient_marker: bool,
    pub explicit_private: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveClipboardDecision {
    pub is_private: bool,
    pub reasons: Vec<String>,
}

pub fn classify_clipboard(input: SensitiveClipboardInput<'_>) -> SensitiveClipboardDecision {
    let mut reasons = Vec::new();
    let content = input.content.trim();
    let source = input
        .source_application
        .unwrap_or_default()
        .to_ascii_lowercase();

    if input.explicit_private {
        reasons.push("explicit_private".to_string());
    }
    if input.concealed_marker {
        reasons.push("concealed_pasteboard_marker".to_string());
    }
    if input.transient_marker {
        reasons.push("transient_pasteboard_marker".to_string());
    }
    if is_password_manager(&source) {
        reasons.push("password_manager_source".to_string());
    }
    if contains_private_key(content) {
        reasons.push("private_key_header".to_string());
    }
    if looks_like_access_token(content) {
        reasons.push("access_token_pattern".to_string());
    }
    if looks_like_recovery_codes(content) {
        reasons.push("recovery_code_pattern".to_string());
    }
    if looks_like_one_time_code(content) && (input.transient_marker || is_password_manager(&source))
    {
        reasons.push("one_time_code".to_string());
    }
    if high_entropy_secret(content) {
        reasons.push("high_entropy_token".to_string());
    }

    SensitiveClipboardDecision {
        is_private: !reasons.is_empty(),
        reasons,
    }
}

fn is_password_manager(source: &str) -> bool {
    [
        "1password",
        "bitwarden",
        "keepass",
        "lastpass",
        "dashlane",
        "proton pass",
        "passwords",
    ]
    .iter()
    .any(|name| source.contains(name))
}

fn contains_private_key(content: &str) -> bool {
    let upper = content.to_ascii_uppercase();
    let pem_begin = "-----BEGIN ";
    let key_kinds = [
        "PRIVATE KEY-----",
        "OPENSSH PRIVATE KEY-----",
        "RSA PRIVATE KEY-----",
        "EC PRIVATE KEY-----",
    ];
    upper
        .split(pem_begin)
        .skip(1)
        .any(|tail| key_kinds.iter().any(|kind| tail.starts_with(kind)))
}

fn looks_like_access_token(content: &str) -> bool {
    let prefixes = [
        "ghp_",
        "gho_",
        "github_pat_",
        "sk-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "AIza",
    ];
    prefixes.iter().any(|prefix| content.starts_with(prefix))
        || content
            .split_whitespace()
            .any(|part| part.starts_with("Bearer") && part.len() > 24)
}

fn looks_like_recovery_codes(content: &str) -> bool {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines.len() >= 3
        && lines.iter().all(|line| {
            let normalized = line.replace('-', "");
            (8..=16).contains(&normalized.len())
                && normalized
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
        })
}

fn looks_like_one_time_code(content: &str) -> bool {
    content.len() == 6 && content.chars().all(|character| character.is_ascii_digit())
}

fn high_entropy_secret(content: &str) -> bool {
    if !(24..=256).contains(&content.len()) || content.chars().any(char::is_whitespace) {
        return false;
    }

    let mut counts = [0_u16; 256];
    for byte in content.bytes() {
        counts[byte as usize] += 1;
    }
    let length = content.len() as f64;
    let entropy = counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = f64::from(*count) / length;
            -probability * probability.log2()
        })
        .sum::<f64>();
    entropy >= 4.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_256_bit_and_compare_in_constant_time() {
        let token = IpcAuthToken::generate();
        let parsed =
            IpcAuthToken::from_encoded(token.expose().to_string()).expect("parse generated token");
        assert!(parsed.matches(token.expose()));
        assert!(!parsed.matches("not-the-token"));
    }

    #[test]
    fn ordinary_clipboard_text_is_not_private() {
        let decision = classify_clipboard(SensitiveClipboardInput {
            content: "meeting notes for Tuesday",
            ..SensitiveClipboardInput::default()
        });
        assert!(!decision.is_private);
    }

    #[test]
    fn private_key_material_is_blocked() {
        let decision = classify_clipboard(SensitiveClipboardInput {
            content: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            ..SensitiveClipboardInput::default()
        });
        assert!(decision.is_private);
        assert!(decision.reasons.contains(&"private_key_header".to_string()));
    }

    #[test]
    fn password_manager_otp_is_blocked() {
        let decision = classify_clipboard(SensitiveClipboardInput {
            content: "123456",
            source_application: Some("Bitwarden"),
            ..SensitiveClipboardInput::default()
        });
        assert!(decision.is_private);
    }
}
