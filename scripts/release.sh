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
# The work is done in two steps, and each can be run alone:
#
#   scripts/release.sh --build     builds the programs and writes the
#                                  notices, and leaves them in
#                                  target/release-built
#   scripts/release.sh --finish    puts the app together from what is in
#                                  target/release-built, signs it, has it
#                                  notarised and packs it
#
# The first step runs code from everything the app is built from: the
# build scripts of its Rust packages, and what builds the window. It needs
# no secret and is given none. The second step takes the secrets, and for
# that reason builds nothing and starts none of the programs the first
# step built. The release workflow on GitHub runs the two on separate
# machines, so that nothing that runs during the build is ever on a
# machine that holds a secret. A Mac that runs both has everything on one
# disk; there the first step is only kept from finding the secrets in its
# environment.
#
# The files of the release end up in target/release-files, under the names
# they have on GitHub, and the text that goes with them in
# target/release-parts/release-notes.md. Among the files is what the
# release before needs to update itself to this one: the app in an
# archive, the signature of that archive, and latest.json, which says
# where they are.
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

usage() {
    echo "usage: scripts/release.sh [--unsigned] [--build | --finish]" >&2
    exit 2
}

signed=yes
steps=both
for argument in "$@"; do
    case "$argument" in
    --unsigned) signed=no ;;
    --build | --finish)
        [ "$steps" = both ] || usage
        steps=${argument#--}
        ;;
    *) usage ;;
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
    bundles=app,dmg
else
    target=$(rustc --print host-tuple)
    bundles=app
fi

# The app's own program, where it is built and where the bundler looks
# for it; what the first step leaves for the second; and the rest.
program="$root/target/$target/release/yca-app"
built="$root/target/release-built"
parts="$root/target/release-parts"
out="$root/target/$target/release/bundle"
files="$root/target/release-files"

if [ "$steps" != finish ]; then
    # The Rust that is found first has to be able to build for it, which
    # one on an Intel Mac does only with the target added.
    sysroot=$(rustc --print sysroot)
    [ -d "$sysroot/lib/rustlib/$target/lib" ] ||
        fail "the Rust at $(command -v rustc) cannot build for $target; see RELEASING.md"
fi

if [ "$signed" = yes ]; then
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

    # A release can be followed by another only if it is signed once more,
    # with a key of the project's own: the app updates itself to nothing
    # that is not signed with the key whose public half it was built with.
    [ -s app/src-tauri/updater.pub ] ||
        fail "app/src-tauri/updater.pub, the public half of the update key, is missing"
fi

# What the second step takes. It is asked for before anything is built, so
# that a run of both steps does not find out at the end.
if [ "$signed" = yes ] && [ "$steps" != build ]; then
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
    [ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ] ||
        fail "TAURI_SIGNING_PRIVATE_KEY is not set: the key updates are signed with, see RELEASING.md"
fi

# What a release has on top of what `tauri dev` and a plain build have. It
# is said here and not in tauri.conf.json, so that working on the app does
# not need the command built first. Both steps are told the same: the
# first builds it into the app's program, the second packs by it.
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

# Runs what builds something, without the secrets the second step is
# given. Where the two steps run on separate machines, there are none to
# leave out.
without_secrets() {
    env -u TAURI_SIGNING_PRIVATE_KEY -u TAURI_SIGNING_PRIVATE_KEY_PASSWORD \
        -u APPLE_CERTIFICATE -u APPLE_CERTIFICATE_PASSWORD -u APPLE_PASSWORD \
        -u APPLE_API_KEY -u APPLE_API_ISSUER -u APPLE_API_KEY_PATH "$@"
}

# The first step: the programs, built from the source, and the notices of
# what they are built from.
build() {
    rm -rf "$parts" "$built"
    mkdir -p "$parts" "$built"

    # The `yca` command, for the app to carry. The bundler looks for it
    # under the name of what it builds for.
    without_secrets cargo build --release --locked -p yca-cli --target "$target"
    cp "target/$target/release/yca" "$parts/yca-$target"

    without_secrets node scripts/third-party-notices.mjs "$parts/THIRD-PARTY-NOTICES.txt" "$target"

    # The app's own program, with the window built into it. It is left as
    # a program: the app is put together from it in the second step.
    without_secrets npm --prefix app run tauri build -- \
        --no-bundle --target "$target" --config "$extra"
    [ -f "$program" ] || fail "no app was built at $program"

    # What was built is what was meant to be. The command is asked here
    # and not later: the second step starts nothing that was built.
    [ "$("$parts/yca-$target" --version)" = "yca $version" ] ||
        fail "the yca command that was built is not $version"
    if [ "$signed" = yes ]; then
        only_for_apple_silicon "$program" "$parts/yca-$target"
    fi

    # What the second step takes, under plain names and in a folder of
    # its own.
    cp "$program" "$built/yca-app"
    cp "$parts/yca-$target" "$built/yca"
    cp "$parts/THIRD-PARTY-NOTICES.txt" "$built/THIRD-PARTY-NOTICES.txt"
    echo
    echo "Built, in $built:"
    (cd "$built" && shasum -a 256 yca-app yca THIRD-PARTY-NOTICES.txt | sed 's/^/  /')
}

# Every program named is for Apple silicon and nothing else.
only_for_apple_silicon() {
    for binary in "$@"; do
        [ "$(lipo -archs "$binary")" = "arm64" ] ||
            fail "$binary is built for $(lipo -archs "$binary"), not for Apple silicon alone"
    done
}

# The second step: the app, put together from what the first step left,
# and for a release signed, notarised and packed.
finish() {
    # The three files by name, and nothing else that may lie beside them.
    # They are put where the bundler looks for them. To this step they are
    # files to pack and to sign: it starts none of them.
    for each in yca-app yca THIRD-PARTY-NOTICES.txt; do
        if [ ! -f "$built/$each" ] || [ -L "$built/$each" ]; then
            fail "target/release-built has no $each; the first step leaves it there, see RELEASING.md"
        fi
    done
    mkdir -p "$parts" "$(dirname "$program")"
    cp "$built/yca-app" "$program"
    cp "$built/yca" "$parts/yca-$target"
    cp "$built/THIRD-PARTY-NOTICES.txt" "$parts/THIRD-PARTY-NOTICES.txt"
    # Files handed from one machine to the next arrive without the mark
    # that says they are programs.
    chmod 755 "$program" "$parts/yca-$target"
    chmod 644 "$parts/THIRD-PARTY-NOTICES.txt"
    echo "Taken from $built:"
    (cd "$built" && shasum -a 256 yca-app yca THIRD-PARTY-NOTICES.txt | sed 's/^/  /')

    # Nothing an earlier run left is taken for what this one makes.
    rm -rf "$out"
    if [ "$signed" = yes ]; then
        npm --prefix app run tauri bundle -- \
            --target "$target" --bundles "$bundles" --config "$extra"
        # The update key has signed the archive, and nothing after this
        # needs it.
        unset TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD
    else
        npm --prefix app run tauri bundle -- \
            --target "$target" --bundles "$bundles" --config "$extra" --no-sign
    fi

    app=$(find "$out/macos" -maxdepth 1 -name "*.app" | head -1)
    [ -d "$app" ] || fail "no app in $out/macos"

    # What is inside is what was meant to be.
    [ -x "$app/Contents/MacOS/yca" ] || fail "the app carries no yca command"
    [ -f "$app/Contents/Resources/LICENSE" ] || fail "the app carries no LICENSE"
    [ -f "$app/Contents/Resources/THIRD-PARTY-NOTICES.txt" ] || fail "the app carries no notices"

    if [ "$signed" = no ]; then
        echo
        echo "Built, unsigned: $app"
        return
    fi

    only_for_apple_silicon "$app/Contents/MacOS/"*

    # Signed all the way down, notarised, and the ticket attached, so that
    # it opens on a Mac that is offline.
    codesign --verify --deep --strict "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute "$app"

    image=$(find "$out/dmg" -maxdepth 1 -name "*.dmg" | head -1)
    [ -f "$image" ] || fail "no disk image in $out/dmg"
    codesign --verify "$image" || codesign --sign "$APPLE_SIGNING_IDENTITY" --timestamp "$image"
    if ! xcrun stapler validate "$image" >/dev/null 2>&1; then
        # The bundler notarised the app; the image around it is a download
        # of its own and gets a ticket of its own.
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

    # What goes on GitHub, under the names it has there. A name with a
    # space in it comes back from GitHub with a dot instead, and the
    # checksum file would no longer name the image.
    rm -rf "$files"
    mkdir -p "$files"
    name="CA-for-YubiKey-$version"
    cp "$image" "$files/$name.dmg"
    (cd "$files" && shasum -a 256 "$name.dmg" >"$name.dmg.sha256")
    cp "$parts/THIRD-PARTY-NOTICES.txt" "$files/"
    sum=$(cut -d " " -f 1 "$files/$name.dmg.sha256")

    # What an installed app takes to update itself: the app in an archive,
    # and the signature of that archive. The app in it has to be the
    # finished one, signed and with Apple's ticket attached: one that
    # arrives this way is put in place without Gatekeeper ever being asked
    # about it.
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

    # What changed, as the changelog says it of this version: the text of
    # the release, and what an installed app shows before it updates
    # itself.
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

    # What an installed app asks for when it looks for a newer version. It
    # is written only if the archive, its signature and the key belong
    # together.
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
}

case "$steps" in
build) build ;;
finish) finish ;;
*)
    build
    finish
    ;;
esac
