use std::fmt;

use zeroize::ZeroizeOnDrop;

/// An owned secret string whose buffer is zeroized when dropped.
///
/// `Passphrase` redacts its [`Debug`](fmt::Debug) output and keeps the secret
/// wrapper attached when values are moved or destructured. Use
/// [`expose_secret`](Self::expose_secret) only where plaintext access is
/// required.
///
/// Zeroization reduces the lifetime of stale secret data in memory, but it
/// cannot protect a live value from a debugger, core dump, or copies made for
/// transport to NetworkManager. Cloning creates another independently
/// zeroized secret allocation. Equality comparisons are not constant-time.
#[non_exhaustive]
#[derive(Clone, Default, Eq, PartialEq, ZeroizeOnDrop)]
pub struct Passphrase(String);

impl Passphrase {
    /// Wraps an owned secret string.
    #[must_use]
    pub fn new(passphrase: String) -> Self {
        Self(passphrase)
    }

    /// Returns the secret length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Borrows the plaintext secret.
    ///
    /// Keep the borrow short-lived and do not log or persist it. Any copy made
    /// from this value must be cleared separately.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Passphrase([REDACTED])")
    }
}

impl From<String> for Passphrase {
    fn from(passphrase: String) -> Self {
        Self::new(passphrase)
    }
}

impl From<&str> for Passphrase {
    fn from(passphrase: &str) -> Self {
        Self::new(passphrase.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_secret() {
        let passphrase = Passphrase::new("correct horse battery staple".to_string());

        let output = format!("{passphrase:?}");

        assert_eq!(output, "Passphrase([REDACTED])");
        assert!(!output.contains("correct horse battery staple"));
    }

    #[test]
    fn exposes_secret_only_when_requested() {
        let passphrase = Passphrase::new("secret".to_string());

        assert_eq!(passphrase.expose_secret(), "secret");
        assert_eq!(passphrase.len(), 6);
        assert!(!passphrase.is_empty());
    }
}
