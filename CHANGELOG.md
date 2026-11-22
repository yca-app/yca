# Changelog

What changed in each release, written for the people who use the app. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.0 (2026-11-18)

The first release, for Macs with Apple silicon and macOS 13.3 or newer.

### Added

- **A CA on YubiKeys.** A wizard creates a root CA on one YubiKey and an issuing CA on a second one, or a root CA alone that signs everything. The private keys are made inside the YubiKeys, in PIV slot 9c, and every signature needs the PIN and a touch.
- **Taking over a CA** that is already on YubiKeys, without writing to them.
- **Certificates by what they are for:** a web server, a VPN gateway, a VPN client, a TLS client. Also signing a device's own request (CSR).
- **Files as the device's upload form asks for them:** `fullchain.crt` with `private-key.key`, or `certificate.crt`, `intermediate-ca.crt` and `private-key.key`, or one password-protected `certificate.p12`. The files of a certificate can be written again in another form without issuing anything.
- **Renewing, changing names, revoking,** and revocation lists (CRL) with a reminder when one is due.
- **Replacing the issuing CA** when its YubiKey is lost or stolen, with the root CA revoking the old one.
- **Groups, filters and sorting** for workspaces with many certificates.
- **Steps for making devices trust the CA** on macOS, Windows, iOS and Android, with the fingerprints to compare.
- **PIN care from the window:** changing a PIN, setting a new one with the PUK, and resetting the PIV application of a YubiKey whose PIN and PUK are both lost.
- **The `yca` command,** for the same work from a terminal, with `--json` output for scripts.
- **Work with AI agents** through `yca mcp`. An agent can read, sort and revoke; whatever needs a signature it hands to the window, where a person types the PIN and touches the key.
