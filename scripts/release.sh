#!/bin/sh
# Builds what a release hands out: the app with the `yca` command, the
# licence and the third-party notices inside it, signed, notarised and
# packed into a disk image. RELEASING.md says what has to be in place and
# what comes before and after.
#
#   scripts/release.sh             the release: Macs with Apple silicon,
#                                  signed
#   scripts/release.sh --unsigned  for trying it out: this Mac, no
#                                  signature, no disk image
#
# The release workflow on GitHub runs it, and so can a Mac that has the
# signing certificate. Either way the files of the release end up in
# target/release-files, under the names they have on GitHub, and the text
# that goes with them in target/release-parts/release-notes.md. Among the
# files is what the release before needs to update itself to this one: the
# app in an archive, the signature of that archive, and latest.json, which
# says where they are.
#
# A release carries no code for Intel. On a Mac with Apple silicon such
# code would run through Rosetta, which macOS 27 warns about and macOS 28
# no longer offers, and a program running through Rosetta that starts the
# `yca` command would get it.
#
# The signing identity, the notarisation credentials and the key that
# updates are signed with come from the environment, where whoever runs
# this put them. Nothing here reads or stores a secret.

set -eu
cd "$(dirname "$0")/.."
root=$(pwd)

signed=yes
for argument in "$@"; do
    case "$argument" in
    --unsigned) signed=no ;;
    *)
        echo "usage: scripts/release.sh [--unsigned]" >&2
        exit 2
        ;;
    esac
done

fail() {
    echo "release: $*" >&2
    exit 1
}

# One version, written in two places and described in the changelog; a
# release is not built until they agree. And where the project lives, which
# is where its releases are, and so where an installed app looks for the
# next one.
about=$(cargo metadata --no-deps --format-version 1 --locked |
    node -e 'const all = JSON.parse(require("fs").readFileSync(0, "utf8")).packages;
             const app = all.find((each) => each.name === "yca-app");
             console.log(app.version, app.repository)')
version=${about%% *}
repository=${about#* }

if [ "$signed" = yes ]; then
    target="aarch64-apple-darwin"
else
    target=$(rustc --print host-tuple)
fi

# The Rust that is found first has to be able to build for it, which one
# on an Intel Mac does only with the target added.
sysroot=$(rustc --print sysroot)
[ -d "$sysroot/lib/rustlib/$target/lib" ] ||
    fail "the Rust at $(command -v rustc) cannot build for $target; see RELEASING.md"

if [ "$signed" = yes ]; then
    bundles=app,dmg

    window=$(node -p 'require("./app/package.json").version')
    config=$(node -p 'require("./app/src-tauri/tauri.conf.json").version ?? ""')
    [ "$window" = "$version" ] || fail "Cargo.toml says $version, app/package.json says $window"
    [ -z "$config" ] || [ "$config" = "$version" ] ||
        fail "Cargo.toml says $version, tauri.conf.json says $config"
    grep -q "^## $version " CHANGELOG.md || fail "CHANGELOG.md has no entry for $version"
    if grep -q "^## $version (not yet released)" CHANGELOG.md; then
        fail "CHANGELOG.md still calls $version not yet released"
    fi
    [ -z "$(git status --porcelain)" ] ||
        fail "the working tree has changes; a release is built from a commit"

    [ -n "${APPLE_SIGNING_IDENTITY:-}" ] || fail "APPLE_SIGNING_IDENTITY is not set"
    security find-identity -v -p codesigning | grep -qF "$APPLE_SIGNING_IDENTITY" ||
        fail "no signing identity named '$APPLE_SIGNING_IDENTITY' in the keychain"
    # How Apple is asked to notarise: with an App Store Connect key, or
    # with an Apple ID and an app-specific password.
    if [ -n "${APPLE_API_KEY:-}" ]; then
        [ -n "${APPLE_API_ISSUER:-}" ] && [ -f "${APPLE_API_KEY_PATH:-}" ] ||
            fail "APPLE_API_KEY needs APPLE_API_ISSUER and the key file at APPLE_API_KEY_PATH"
    elif [ -n "${APPLE_ID:-}" ]; then
        [ -n "${APPLE_PASSWORD:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] ||
            fail "APPLE_ID needs APPLE_PASSWORD and APPLE_TEAM_ID"
    else
        fail "no notarisation credentials: set APPLE_API_KEY or APPLE_ID, see RELEASING.md"
    fi

    # A release can be followed by another only if it is signed once more,
    # with a key of the project's own: the app updates itself to nothing
    # that is not signed with the key whose public half it was built with.
    [ -s app/src-tauri/updater.pub ] ||
        fail "app/src-tauri/updater.pub, the public half of the update key, is missing"
    [ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ] ||
        fail "TAURI_SIGNING_PRIVATE_KEY is not set: the key updates are signed with, see RELEASING.md"
else
    bundles=app
fi

# The `yca` command, for the app to carry. The bundler looks for it under
# the name of what it builds for.
parts="$root/target/release-parts"
rm -rf "$parts"
mkdir -p "$parts"
cargo build --release --locked -p yca-cli --target "$target"
cp "target/$target/release/yca" "$parts/yca-$target"

node scripts/third-party-notices.mjs "$parts/THIRD-PARTY-NOTICES.txt" "$target"

# What a release has on top of what `tauri dev` and a plain build have. It
# is said here and not in tauri.conf.json, so that working on the app does
# not need the command built first.
#
# Only a release updates itself, and so only a release is told where to
# ask for the latest one and which key it has to be signed with. The
# version in the signature has to be the version that is offered, so that
# an older release cannot be passed off as a newer one. An app built
# without this has no updater and makes no connection of its own.
# shellcheck disable=SC2016
extra=$(
    PARTS="$parts" ROOT="$root" SIGNED="$signed" REPOSITORY="$repository" node -e '
        const { PARTS, ROOT, SIGNED, REPOSITORY } = process.env;
        const extra = {
            bundle: {
                externalBin: [`${PARTS}/yca`],
                resources: {
                    [`${ROOT}/LICENSE`]: "LICENSE",
                    [`${PARTS}/THIRD-PARTY-NOTICES.txt`]: "THIRD-PARTY-NOTICES.txt",
                },
            },
        };
        if (SIGNED === "yes") {
            const key = `${ROOT}/app/src-tauri/updater.pub`;
            extra.bundle.createUpdaterArtifacts = true;
            extra.plugins = {
                updater: {
                    pubkey: require("fs").readFileSync(key, "utf8").trim(),
                    endpoints: [`${REPOSITORY}/releases/latest/download/latest.json`],
                    requireSignedVersion: true,
                },
            };
        }
        console.log(JSON.stringify(extra));'
)
npm --prefix app run tauri build -- --target "$target" --bundles "$bundles" --config "$extra"

out="$root/target/$target/release/bundle"
app=$(find "$out/macos" -maxdepth 1 -name "*.app" | head -1)
[ -d "$app" ] || fail "no app in $out/macos"

# What is inside is what was meant to be.
inside="$app/Contents/MacOS/yca"
[ -x "$inside" ] || fail "the app carries no yca command"
[ "$("$inside" --version)" = "yca $version" ] || fail "the yca command inside is not $version"
[ -f "$app/Contents/Resources/LICENSE" ] || fail "the app carries no LICENSE"
[ -f "$app/Contents/Resources/THIRD-PARTY-NOTICES.txt" ] || fail "the app carries no notices"

if [ "$signed" = yes ]; then
    # Every program in it is for Apple silicon and nothing else.
    for binary in "$app/Contents/MacOS/"*; do
        [ "$(lipo -archs "$binary")" = "arm64" ] ||
            fail "$binary is built for $(lipo -archs "$binary"), not for Apple silicon alone"
    done
fi

if [ "$signed" = no ]; then
    echo
    echo "Built, unsigned: $app"
    exit 0
fi

# Signed all the way down, notarised, and the ticket attached, so that it
# opens on a Mac that is offline.
codesign --verify --deep --strict "$app"
xcrun stapler validate "$app"
spctl --assess --type execute "$app"

image=$(find "$out/dmg" -maxdepth 1 -name "*.dmg" | head -1)
[ -f "$image" ] || fail "no disk image in $out/dmg"
codesign --verify "$image" || codesign --sign "$APPLE_SIGNING_IDENTITY" --timestamp "$image"
if ! xcrun stapler validate "$image" >/dev/null 2>&1; then
    # The bundler notarised the app; the image around it is a download of
    # its own and gets a ticket of its own.
    if [ -n "${APPLE_API_KEY:-}" ]; then
        xcrun notarytool submit "$image" --wait \
            --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER"
    else
        xcrun notarytool submit "$image" --wait \
            --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID"
    fi
    xcrun stapler staple "$image"
fi
spctl --assess --type open --context context:primary-signature "$image"

# What goes on GitHub, under the names it has there. A name with a space in
# it comes back from GitHub with a dot instead, and the checksum file would
# no longer name the image.
files="$root/target/release-files"
rm -rf "$files"
mkdir -p "$files"
name="CA-for-YubiKey-$version"
cp "$image" "$files/$name.dmg"
(cd "$files" && shasum -a 256 "$name.dmg" >"$name.dmg.sha256")
cp "$parts/THIRD-PARTY-NOTICES.txt" "$files/"
sum=$(cut -d " " -f 1 "$files/$name.dmg.sha256")

# What an installed app takes to update itself: the app in an archive, and
# the signature of that archive. The app in it has to be the finished one,
# signed and with Apple's ticket attached: one that arrives this way is
# put in place without Gatekeeper ever being asked about it.
archive=$(find "$out/macos" -maxdepth 1 -name "*.app.tar.gz" | head -1)
[ -f "$archive" ] && [ -f "$archive.sig" ] ||
    fail "no update archive with its signature in $out/macos"
unpacked=$(mktemp -d)
tar -xzf "$archive" -C "$unpacked"
codesign --verify --deep --strict "$unpacked/$(basename "$app")"
xcrun stapler validate "$unpacked/$(basename "$app")"
rm -rf "$unpacked"
cp "$archive" "$files/$name.app.tar.gz"
cp "$archive.sig" "$files/$name.app.tar.gz.sig"

# What changed, as the changelog says it of this version: the text of the
# release, and what an installed app shows before it updates itself.
# shellcheck disable=SC2016
VERSION="$version" node -e '
    const lines = require("fs").readFileSync("CHANGELOG.md", "utf8").split("\n");
    const rest = lines.slice(lines.findIndex((line) => line.startsWith(`## ${process.env.VERSION} `)) + 1);
    const next = rest.findIndex((line) => line.startsWith("## "));
    console.log(rest.slice(0, next < 0 ? undefined : next).join("\n").trim());' >"$parts/changes.md"

# The text of the release adds what to hold the download against.
macos=$(node -p 'require("./app/src-tauri/tauri.conf.json").bundle.macOS.minimumSystemVersion')
{
    cat "$parts/changes.md"
    # shellcheck disable=SC2016
    printf '\n### Checking the download\n\nSHA-256 of `%s`:\n\n```\n%s\n```\n\n' "$name.dmg" "$sum"
    echo "The app is signed with a Developer ID and notarised by Apple. It runs on Macs with Apple silicon and macOS $macos or newer."
} >"$parts/release-notes.md"

# What an installed app asks for when it looks for a newer version. It is
# written only if the archive, its signature and the key belong together.
node scripts/update-manifest.mjs \
    --archive "$files/$name.app.tar.gz" --signature "$files/$name.app.tar.gz.sig" \
    --key app/src-tauri/updater.pub --version "$version" \
    --url "$repository/releases/download/v$version/$name.app.tar.gz" \
    --notes "$parts/changes.md" --out "$files/latest.json"

echo
echo "Release $version, in $files:"
find "$files" -type f -exec basename {} \; | sort | sed 's/^/  /'
echo "SHA-256 of the disk image: $sum"
codesign --display --verbose=2 "$app" 2>&1 | grep -E "^(Authority|TeamIdentifier)=" | sed 's/^/  /'
