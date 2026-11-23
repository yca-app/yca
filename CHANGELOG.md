# Changelog

What changed in each release, written for the people who use the app. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.1 (not yet released)

### Changed

- **The touch for a new issuing CA is asked for plainly.** The root CA signs a new issuing CA, so it is the root's YubiKey that has to be touched, not the one that is being written to. The wizard now says so as a heading at the moment that YubiKey starts to blink, shows only its serial number, and names it if the touch did not come. The `yca init-issuing` command says it at the same moment.
- **A new CA no longer starts out with a warning about revocation lists.** The window said that a CA "has not signed a revocation list yet" as soon as it had signed anything, which for the root CA was right after the wizard. It now says so only of an issuing CA that took the place of one with a list, which devices may be checking. A CA that has revoked nothing owes nobody a list.

### Fixed

- **A YubiKey pulled out in the middle of the wizard** left its step empty, and once plugged in again, the step had forgotten what had happened. The step now stays, says which YubiKey to connect, and keeps what was typed.
- **A CA that was not finished can be started again.** If the touch for a new CA did not come, its key stayed on the YubiKey without a certificate. After leaving the step, the wizard then refused that YubiKey with "slot 9c of this YubiKey is already in use" while showing its slot as empty. The window and `yca devices` now show such a key for what it is, and the wizard replaces it once the serial number is typed, as it does with anything else in the slot.
- **Trying a step of the wizard again** no longer asks a second time where the workspace folder goes, or for the PIN and PUK a new YubiKey was already given.

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
