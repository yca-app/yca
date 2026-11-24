// Puts the bundler, and nothing else, on the machine where a release is
// signed.
//
//   node scripts/bundler-alone.mjs <folder>
//
// The bundler is the Tauri CLI: one package, and the program for this kind
// of Mac that belongs to it. The lock file of the app names both, with
// their checksums. This fetches those two, holds them against the lock
// file, unpacks them into <folder> and prints where the bundler starts.
//
// Installing what the lock file names, all of it, would bring every
// package the window is built from to the machine that holds the keys.
// None of them would be started on purpose. But npm links the commands
// they bring into one folder and puts that folder in front of the
// system's own when it runs something, so a package that brought a
// command named `codesign` would be started in its place; and the bundler
// looks for its program under more than one package name. With the two
// packages alone, in a folder of their own, there is nothing to take
// either place.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  console.error(`bundler: ${message}`);
  process.exit(1);
}

const folder = process.argv[2];
if (!folder || process.argv.length > 3) {
  console.error("usage: node scripts/bundler-alone.mjs <folder>");
  process.exit(2);
}

// The program is built per kind of Mac, and a release is made on a Mac.
const kind = { "darwin arm64": "darwin-arm64", "darwin x64": "darwin-x64" }[
  `${process.platform} ${process.arch}`
];
if (!kind) fail(`no bundler for ${process.platform} on ${process.arch} is fetched here`);

const lock = JSON.parse(readFileSync(join(root, "app/package-lock.json"), "utf8"));
const registry = "https://registry.npmjs.org/";

for (const name of ["@tauri-apps/cli", `@tauri-apps/cli-${kind}`]) {
  const named = lock.packages?.[`node_modules/${name}`];
  if (!named?.resolved || !named?.integrity) {
    fail(`app/package-lock.json does not name ${name}`);
  }
  if (!named.resolved.startsWith(registry)) {
    fail(`${name} comes from ${named.resolved}, not from ${registry}`);
  }
  const checksum = named.integrity
    .split(/\s+/)
    .find((each) => each.startsWith("sha512-"))
    ?.slice("sha512-".length);
  if (!checksum) fail(`the lock file has no SHA-512 checksum for ${name}`);

  const answer = await fetch(named.resolved);
  if (!answer.ok) fail(`${named.resolved} answered ${answer.status}`);
  const archive = Buffer.from(await answer.arrayBuffer());
  if (createHash("sha512").update(archive).digest("base64") !== checksum) {
    fail(`${name} ${named.version} from the registry is not what the lock file names`);
  }

  // Where Node finds a package: under node_modules, by its name.
  const place = join(folder, "node_modules", name);
  rmSync(place, { recursive: true, force: true });
  mkdirSync(place, { recursive: true });
  const kept = join(folder, "package.tgz");
  writeFileSync(kept, archive);
  // What a package holds lies in a folder named "package" in its archive.
  execFileSync("/usr/bin/tar", ["-xzf", kept, "-C", place, "--strip-components=1"]);
  rmSync(kept);
  console.error(`bundler: ${name} ${named.version}, as the lock file names it`);
}

console.log(resolve(folder, "node_modules/@tauri-apps/cli/tauri.js"));
