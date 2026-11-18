#!/bin/sh
# Builds what a release hands out: the app with the `yca` command, the
# licence and the third-party notices inside it, signed, notarised and
# packed into a disk image. RELEASING.md says what has to be in place and
# what comes before and after.
#
#   scripts/release.sh             the release: both kinds of Mac, signed
#   scripts/release.sh --unsigned  for trying it out: this Mac only, no
#                                  signature, no disk image
#   scripts/release.sh --unsigned --universal
#                                  the same for both kinds of Mac: what a
#                                  release builds, short of signing it
#
# The signing identity and the notarisation credentials come from the
# environment, where the person who runs this put them. Nothing here reads
# or stores a secret.

set -eu
cd "$(dirname "$0")/.."
root=$(pwd)

signed=yes
wide=no
for argument in "$@"; do
    case "$argument" in
    --unsigned) signed=no ;;
    --universal) wide=yes ;;
    *)
        echo "usage: scripts/release.sh [--unsigned [--universal]]" >&2
        exit 2
        ;;
    esac
done
# A release is always for both kinds of Mac.
universal=$wide
[ "$signed" = no ] || universal=yes

fail() {
    echo "release: $*" >&2
    exit 1
}

# One version, written in two places and described in the changelog; a
# release is not built until they agree.
version=$(cargo metadata --no-deps --format-version 1 --locked |
    node -e 'const all = JSON.parse(require("fs").readFileSync(0, "utf8")).packages;
             console.log(all.find((each) => each.name === "yca-app").version)')

if [ "$universal" = yes ]; then
    target="universal-apple-darwin"
    halves="aarch64-apple-darwin x86_64-apple-darwin"
else
    target=$(rustc --print host-tuple)
    halves=$target
fi

# The Rust that is found first has to be able to build for each of them.
# One installed without rustup, as from Homebrew, builds for the Mac it
# runs on and nothing else, and says so only minutes into the build.
sysroot=$(rustc --print sysroot)
for half in $halves; do
    [ -d "$sysroot/lib/rustlib/$half/lib" ] ||
        fail "the Rust at $(command -v rustc) cannot build for $half; see RELEASING.md"
done

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
else
    bundles=app
fi

# The `yca` command, for the app to carry. The bundler looks for it under
# the name of what it builds for.
parts="$root/target/release-parts"
rm -rf "$parts"
mkdir -p "$parts"
for half in $halves; do
    cargo build --release --locked -p yca-cli --target "$half"
    cp "target/$half/release/yca" "$parts/yca-$half"
done
if [ "$universal" = yes ]; then
    # The app is built once for each kind of Mac, and each of those builds
    # looks for the command under its own name; the bundler then takes the
    # one that is both.
    # shellcheck disable=SC2046
    lipo -create -output "$parts/yca-$target" \
        $(for half in $halves; do echo "$parts/yca-$half"; done)
fi

node scripts/third-party-notices.mjs "$parts/THIRD-PARTY-NOTICES.txt"

# What a release has on top of what `tauri dev` and a plain build have. It
# is said here and not in tauri.conf.json, so that working on the app does
# not need the command built first.
# shellcheck disable=SC2016
extra=$(
    PARTS="$parts" ROOT="$root" node -e '
        const { PARTS, ROOT } = process.env;
        console.log(JSON.stringify({
            bundle: {
                externalBin: [`${PARTS}/yca`],
                resources: {
                    [`${ROOT}/LICENSE`]: "LICENSE",
                    [`${PARTS}/THIRD-PARTY-NOTICES.txt`]: "THIRD-PARTY-NOTICES.txt",
                },
            },
        }));'
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

if [ "$universal" = yes ]; then
    for binary in "$app/Contents/MacOS/"*; do
        [ "$(lipo -archs "$binary")" = "x86_64 arm64" ] || [ "$(lipo -archs "$binary")" = "arm64 x86_64" ] ||
            fail "$binary is not built for both kinds of Mac"
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

echo
echo "Release $version:"
echo "  $image"
(cd "$(dirname "$image")" && shasum -a 256 "$(basename "$image")")
codesign --display --verbose=2 "$app" 2>&1 | grep -E "^(Authority|TeamIdentifier)=" | sed 's/^/  /'
