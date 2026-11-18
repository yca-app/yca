# Releasing

How a release of CA for YubiKey is made. It is built by hand on the maintainer's Mac: the signing key stays there, and nothing in the repository or in its automated checks can sign or publish anything.

A release is one disk image with the app in it. The app is built for both kinds of Mac (Apple silicon and Intel), signed with a Developer ID, notarised by Apple, and carries the `yca` command, the licence and the notices of the software it is built from.

## What has to be in place

Once, on the Mac that builds releases:

1. **A Developer ID Application certificate** in the login keychain. It comes with membership of the Apple Developer Program and is made in Xcode (Settings, Accounts, Manage Certificates) or on developer.apple.com. This shows it, with the name to use below:

   ```sh
   security find-identity -v -p codesigning
   ```

2. **Credentials for notarisation.** Either a key for App Store Connect (in App Store Connect under Users and Access, Integrations: an issuer ID, a key ID and a `.p8` file that can be downloaded once), or an Apple ID with an app-specific password. The key is the better of the two, because nothing has to be typed or kept in a variable.

3. **A file that sets them,** outside the repository and readable by you alone, for example `~/.config/yca/release.env`:

   ```sh
   export APPLE_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)"
   export APPLE_API_ISSUER="…"
   export APPLE_API_KEY="…"
   export APPLE_API_KEY_PATH="$HOME/.config/yca/AuthKey_….p8"
   ```

   With an Apple ID it sets `APPLE_ID`, `APPLE_PASSWORD` and `APPLE_TEAM_ID` instead of the three `APPLE_API_` lines.

4. **Rust from rustup, with both targets.** A Rust installed another way builds only for the Mac it runs on.

   ```sh
   rustup target add aarch64-apple-darwin x86_64-apple-darwin
   ```

5. **Node.js,** in the version the checks use (see `.github/workflows/checks.yml`).

Once, on GitHub: private vulnerability reporting switched on for the repository, which [SECURITY.md](SECURITY.md) sends people to.

## Every release

### 1. Version and changelog

The version is written in two places: `version` under `[workspace.package]` in `Cargo.toml`, and `version` in `app/package.json`. After changing them, bring the lock files along:

```sh
cargo check --workspace
npm --prefix app install --package-lock-only
```

In [CHANGELOG.md](CHANGELOG.md), give the entry of the version its date in place of "not yet released", and read it once more as someone who uses the app would.

### 2. Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix app run build
```

Commit. The release is built from this commit.

### 3. Build

From a fresh clone of that commit, so that nothing gets in that is not in the repository:

```sh
npm --prefix app ci
. ~/.config/yca/release.env
scripts/release.sh
```

The script refuses to start if the two versions differ, the changelog has no dated entry, the working tree has changes, or the signing identity or the notarisation credentials are missing. Then it builds the `yca` command for both kinds of Mac, writes the third-party notices, builds, signs and notarises the app, and checks the result: that the app carries the command in the right version, the licence and the notices, that every program in it runs on both kinds of Mac, that the signature holds all the way down, and that the app and the disk image both have Apple's ticket attached and pass Gatekeeper.

It ends by naming the disk image, its SHA-256 and the team the signature belongs to. The image is in `target/universal-apple-darwin/release/bundle/dmg`.

`scripts/release.sh --unsigned` builds the app the same way for this Mac only, without signature and disk image. It is for trying the build out, and for whoever builds the app themselves.

### 4. Try what was built

The tests run without a YubiKey, so what only hardware shows has to be tried by hand, on the app from the disk image and not on a development build:

- Download the image the way a user would (a browser marks it as downloaded) and open the app on a Mac that did not build it. It must open without a warning beyond the usual question about an app from the internet.
- Go through the wizard with two YubiKeys, and with one. Use one that still has its factory PIN and one that has a PIN of its own, and both firmware lines in use (5.4 and 5.7).
- Issue a certificate in each of the three forms of files, and check one chain with `openssl verify`. Sign a request a device made.
- Renew a certificate, revoke one, and sign the revocation list.
- Replace the issuing CA.
- Change a PIN, set a new one with the PUK, and reset a YubiKey you can afford to reset.
- Run the command from inside the app, also as an Intel Mac would:

  ```sh
  "/Applications/CA for YubiKey.app/Contents/MacOS/yca" devices
  arch -x86_64 "/Applications/CA for YubiKey.app/Contents/MacOS/yca" devices
  ```

- Point an MCP client at that command and ask it for a certificate: the window must open with the signing dialog.

If anything fails, fix it and start again from step 2. A version that was published is never built a second time; a fix gets the next version.

### 5. Publish

```sh
git tag -a v1.0.0 -m "CA for YubiKey 1.0.0"
git push origin main v1.0.0
```

On GitHub, make a release from the tag with the changelog entry as its text, and attach the disk image, a file with its SHA-256, and `THIRD-PARTY-NOTICES.txt` from `target/release-parts`.

Afterwards, see that the README tells people where to download it and no longer says what has not been tried.
