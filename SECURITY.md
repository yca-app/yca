# Security

CA for YubiKey signs certificates that other devices then trust, so a flaw in it matters more than in most apps. If you find one, please say so privately first.

## Reporting a vulnerability

Use [**Report a vulnerability**](https://github.com/yca-app/yca/security/advisories/new) on the Security tab of the project's repository on GitHub. The report is private: only the maintainers see it until a fix is out.

Please do not open a public issue for it, and do not send PINs, private keys or a workspace you use. What helps:

- what you did and what happened, in steps someone else can repeat,
- the version of the app (`yca --version`, or About in the app's menu) and of macOS,
- the model and firmware of the YubiKey, if it plays a part.

The project is looked after in spare time, so allow a few days for an answer. You are welcome to be named in the release notes of the fix, or not, as you prefer.

Fixes go into the next release. Only the latest release is supported.

## What the app promises

A report is a vulnerability if it breaks one of these:

- **A CA key never exists outside its YubiKey,** and nothing is signed with it without the PIN and a touch at the key.
- **What the signing dialog shows is what gets signed.** That goes for requests from the window, the command line and AI agents alike.
- **No PIN, PUK or password goes to a program.** Nothing in the command line's JSON output, the MCP server or the app's socket takes or gives out a secret.
- **A YubiKey is written to only where a CA needs it:** PIV slot 9c, and the PIN, PUK and management key. The other PIV slots are touched by nothing but the reset of the PIV application, which says what it destroys and asks for the serial number. FIDO2, OpenPGP and OATH are never touched.
- **Files are written only inside the workspace folder** the person chose, whatever a certificate, a group or a request is named.
- **A certificate that is not what was asked for is not issued:** the names, the purpose and the validity in it are the ones shown.

## What it does not promise

These are known limits, described in the [README](README.md#what-to-keep-in-mind). They are worth improving, in the open, but they are not vulnerabilities:

- The workspace folder holds the private keys of the certificates the app made keys for. Whoever can read the folder can pose as those devices until the certificates are revoked.
- The list of issued and revoked certificates in the workspace is not signed. Whoever can change the folder can hide a revocation. They cannot issue anything.
- A program running as you can make the window show a signing dialog. It cannot type the PIN or touch the key.
- A YubiKey's statement that a key was made inside it is kept, but not checked against Yubico's root certificate.
- The libraries the app is built on have not been audited, and the one that talks to the YubiKey is used in a pre-release version.
