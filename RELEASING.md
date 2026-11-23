# Releasing

How a release of CA for YubiKey is made. GitHub builds it, in the workflow [Release](.github/workflows/release.yml), from a commit on `main`, when a maintainer starts that workflow. The workflow signs the app with a Developer ID certificate and has Apple notarise it; both take secrets that are handed to that workflow alone, and only when it runs from `main`. Nothing becomes public by itself: the workflow leaves a draft, a person tries what was built, and publishes it.

A release is one disk image with the app in it. The app is built for Macs with Apple silicon, signed with a Developer ID, notarised by Apple, and carries the `yca` command, the licence and the notices of the software it is built from.

It carries no code for Intel. On a Mac with Apple silicon such code would run through Rosetta, which macOS 27 warns about with a notice naming the app and macOS 28 no longer offers. A program that itself runs through Rosetta and starts the `yca` command would get that code, so it is left out altogether.

## What has to be in place

Once, on GitHub, by an owner of the repository:

1. **An environment named `release`** (Settings, Environments), with its deployment branches limited to `main`. The secrets below go into this environment and not among the secrets of the repository, so that no other workflow and no other branch is given them. With yourself as a required reviewer, a run waits for one more click before it gets them.

2. **The signing certificate,** as two secrets of that environment. It is the Developer ID Application certificate that comes with membership of the Apple Developer Program, exported from Keychain Access together with its private key as a `.p12` file, with a password chosen for that file:

   ```sh
   base64 -i certificate.p12 | gh secret set APPLE_CERTIFICATE --env release
   gh secret set APPLE_CERTIFICATE_PASSWORD --env release
   ```

   The second command asks for the password without showing it. Delete the `.p12` file afterwards; the certificate stays in the keychain it came from.

3. **A key for notarisation,** as three secrets: a key for App Store Connect (in App Store Connect under Users and Access, Integrations), which is an issuer ID, a key ID and a `.p8` file that can be downloaded once:

   ```sh
   gh secret set APPLE_API_ISSUER --env release
   gh secret set APPLE_API_KEY --env release
   gh secret set APPLE_API_KEY_P8 --env release < AuthKey_….p8
   ```

4. **Private vulnerability reporting** switched on for the repository, which [SECURITY.md](SECURITY.md) sends people to.

A secret can be replaced but not read back, by anybody. The workflow keeps the name the certificate is in, which every copy of the app shows anyway, out of its log.

Whoever takes the project over puts a certificate and a key of their own into these secrets. Nothing else has to change, but the app is then signed in their name.

## Every release

### 1. Version and changelog

The version is written in two places: `version` under `[workspace.package]` in `Cargo.toml`, and `version` in `app/package.json`. After changing them, bring the lock files along:

```sh
cargo check --workspace
npm --prefix app install --package-lock-only
```

In [CHANGELOG.md](CHANGELOG.md), give the entry of the version its date in place of "not yet released", and read it once more as someone who uses the app would. It becomes the text of the release.

### 2. Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix app run build
```

Commit and push to `main`, and wait for the checks on GitHub to pass. The release is built from this commit, and the workflow refuses a commit that has not passed them.

### 3. Build

Start the workflow: on the Actions page of the repository (Release, Run workflow, on `main`), or with

```sh
gh workflow run release.yml --ref main
```

It runs `scripts/release.sh` on a fresh copy of the commit, with nothing taken from a cache. The script refuses to start if the two versions differ, the changelog has no dated entry, the working tree has changes, or the signing identity or the notarisation credentials are missing. Then it builds the `yca` command, writes the third-party notices, builds, signs and notarises the app, and checks the result: that the app carries the command in the right version, the licence and the notices, that every program in it is built for Apple silicon and nothing else, that the signature holds all the way down, and that the app and the disk image both have Apple's ticket attached and pass Gatekeeper.

What it leaves is a draft release named after the version, which only maintainers see. Its text is the changelog entry followed by the SHA-256 of the disk image, and it has three files:

- `CA-for-YubiKey-<version>.dmg`, the disk image,
- `CA-for-YubiKey-<version>.dmg.sha256`, its checksum,
- `THIRD-PARTY-NOTICES.txt`.

No tag exists yet. The workflow also refuses to build a version that is published already.

With "rehearsal" ticked (`gh workflow run release.yml --ref main -f rehearsal=true`), the workflow builds, signs and notarises in the same way but drafts nothing: the files stay with the run for a day. It is for trying out a change to the workflow or to the script.

### 4. Try what was built

The tests run without a YubiKey, so what only hardware shows has to be tried by hand, on the app from the disk image of the draft and not on a development build:

- Download the image the way a user would (a browser marks it as downloaded) and open the app. It must open without a warning beyond the usual question about an app from the internet.
- Go through the wizard with two YubiKeys, and with one. Use one that still has its factory PIN and one that has a PIN of its own, and both firmware lines in use (5.4 and 5.7).
- Issue a certificate in each of the three forms of files, and check one chain with `openssl verify`. Sign a request a device made.
- Renew a certificate, revoke one, and sign the revocation list.
- Replace the issuing CA.
- Change a PIN, set a new one with the PUK, and reset a YubiKey you can afford to reset.
- Run the command from inside the app:

  ```sh
  "/Applications/CA for YubiKey.app/Contents/MacOS/yca" devices
  ```

- Point an MCP client at that command and ask it for a certificate: the window must open with the signing dialog.

If anything fails, fix it and go on from step 2: a run from the new commit puts its draft in place of the old one. A version that was published is never built a second time; a fix gets the next version.

### 5. Publish

Tag the commit the draft was built from, which the draft names as its target, and publish the draft:

```sh
git tag -a v1.0.1 -m "CA for YubiKey 1.0.1" <commit>
git push origin v1.0.1
gh release edit v1.0.1 --draft=false --latest
```

Published without the tag pushed first, the release gets a tag from GitHub, on the same commit but without a message.

Afterwards, see that the README tells people where to download it and no longer says what has not been tried.

## Building a release on a Mac

The workflow does nothing a Mac could not do. With the Developer ID Application certificate in the login keychain (`security find-identity -v -p codesigning` shows it, with the name to use below), Rust 1.90 or newer and the Node.js of the checks, the same script builds the same release from a fresh clone of the commit:

```sh
npm --prefix app ci
. ~/.config/yca/release.env
scripts/release.sh
```

The file that is read first sets what the workflow takes from its secrets. It is kept outside the repository and readable by its owner alone:

```sh
export APPLE_SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)"
export APPLE_API_ISSUER="…"
export APPLE_API_KEY="…"
export APPLE_API_KEY_PATH="$HOME/.config/yca/AuthKey_….p8"
```

With an Apple ID and an app-specific password in place of the key for App Store Connect, it sets `APPLE_ID`, `APPLE_PASSWORD` and `APPLE_TEAM_ID` instead of the three `APPLE_API_` lines. On an Intel Mac the Rust has to be one from rustup, found first, with the target added (`rustup target add aarch64-apple-darwin`).

The files of the release are left in `target/release-files` and its text in `target/release-parts/release-notes.md`, as the workflow attaches them.

`scripts/release.sh --unsigned` builds the app the same way for the Mac it runs on, without signature and disk image. It is for trying the build out, and for whoever builds the app themselves.
