#!/usr/bin/env node
// Writes what an installed app asks for when it looks for a newer version:
// one small file that names the version, says what changed, and tells where
// the archive with the new app is and which signature it has to carry.
//
//   node scripts/update-manifest.mjs --archive <app.tar.gz> --signature <.sig>
//       --key <updater.pub> --version <1.2.3> --url <where the archive will be>
//       --notes <file with what changed> --out <latest.json>
//
// Before it writes anything, it checks what a slip in a release would
// otherwise leave for the installed apps to find out, each of them refusing
// the update: that the signature was made with the key whose public half the
// app is built with, that it is the signature of this very archive, and that
// it carries this version. The signature is one of minisign, as the Tauri
// bundler makes them.

import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

function fail(why) {
  console.error(`update-manifest: ${why}`);
  process.exit(1);
}

const options = {};
for (let at = 2; at < process.argv.length; at += 2) {
  options[process.argv[at].replace(/^--/, "")] = process.argv[at + 1];
}
for (const name of ["archive", "signature", "key", "version", "url", "notes", "out"]) {
  if (!options[name]) fail(`--${name} is missing`);
}

// Tauri keeps a key and a signature as minisign writes them, the whole file
// in base64 once more.
const lines = (file) =>
  Buffer.from(readFileSync(file, "utf8").trim(), "base64").toString("utf8").split("\n");

// A public key: two letters for the kind, eight bytes that name the key,
// and the key itself.
const publicKey = Buffer.from(lines(options.key)[1] ?? "", "base64");
// A signature: the same two fields, and the signature itself. Under it, a
// comment that is signed as well, and the signature over both.
const [, first, comment = "", second] = lines(options.signature);
const signature = Buffer.from(first ?? "", "base64");
const overBoth = Buffer.from(second ?? "", "base64");
if (publicKey.length !== 42 || signature.length !== 74 || overBoth.length !== 64) {
  fail("the key or the signature is not in the form the Tauri bundler writes");
}
if (!publicKey.subarray(2, 10).equals(signature.subarray(2, 10))) {
  fail(
    "the archive is signed with another key than the one in " +
      `${options.key}, which the app is built with. Installed apps would refuse it.`,
  );
}

const key = createPublicKey({
  // What comes before a bare Ed25519 key in the form the library reads.
  key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), publicKey.subarray(10)]),
  format: "der",
  type: "spki",
});
const archive = readFileSync(options.archive);
// "ED" signs a hash of the file, which is what is made today; "Ed" signed
// the file itself.
const signed =
  signature.subarray(0, 2).toString("latin1") === "ED"
    ? createHash("blake2b512").update(archive).digest()
    : archive;
if (!verify(null, signed, key, signature.subarray(10))) {
  fail(`the signature is not one of ${options.archive}`);
}
const said = comment.replace(/^trusted comment: /, "");
if (!verify(null, Buffer.concat([signature.subarray(10), Buffer.from(said)]), key, overBoth)) {
  fail("the comment of the signature is not the one that was signed");
}
// The app holds the version in the comment against the version announced
// here, so that an older archive cannot be passed off as a newer release.
const version = said
  .split("\t")
  .find((field) => field.startsWith("version:"))
  ?.slice("version:".length);
if (version !== options.version) {
  fail(`the signature is for version ${version ?? "none"}, not for ${options.version}`);
}

const manifest = {
  version: options.version,
  notes: readFileSync(options.notes, "utf8").trim(),
  pub_date: new Date().toISOString(),
  platforms: {
    "darwin-aarch64": {
      signature: readFileSync(options.signature, "utf8").trim(),
      url: options.url,
    },
  },
};
writeFileSync(options.out, `${JSON.stringify(manifest, null, 2)}\n`);
