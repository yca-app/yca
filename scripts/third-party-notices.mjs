#!/usr/bin/env node
// Writes the notices of the third-party software a release is built from:
// the Rust crates linked into the app and the `yca` command, and the
// JavaScript packages whose code ends up in the window. Their licences ask
// that the notice travels with every copy, so the file goes into the app
// bundle and beside the download.
//
//   node scripts/third-party-notices.mjs [where to write it] [target]
//
// Without arguments it writes target/THIRD-PARTY-NOTICES.txt for what a
// release is built for, aarch64-apple-darwin. It needs what a build needs
// and nothing more: `cargo` with the dependencies fetched, and
// `npm --prefix app install` done.
//
// What is listed is what is shipped, not what is installed. For Rust that
// is what the two programs depend on in order to run on the target, leaving
// out what only builds or tests them. For the
// window it is the modules the bundler put into the bundle, which it is
// asked for, and the packages the style sheet imports.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const app = join(root, "app");
const output = resolve(process.argv[2] ?? join(root, "target", "THIRD-PARTY-NOTICES.txt"));

/** The programs a release hands out. */
const shipped = ["yca-app", "yca-cli"];
/** What they are built for. */
const target = process.argv[3] ?? "aarch64-apple-darwin";

/** A file that states a licence or a notice, by its name. */
const stated = /^(licen[sc]e|copying|notice|unlicense|copyright)([-_. ].*)?$/i;
const notText = /\.(rs|js|mjs|cjs|ts|json|toml|ya?ml|png|svg)$/i;

/** The licence files of a package: those at its top, and those in a folder
 *  named like one. */
function licenceFiles(folder) {
  const files = [];
  for (const entry of readdirSync(folder).sort()) {
    if (!stated.test(entry) || notText.test(entry)) continue;
    const path = join(folder, entry);
    if (statSync(path).isDirectory()) {
      for (const inner of readdirSync(path).sort()) {
        const file = join(path, inner);
        if (statSync(file).isFile() && !notText.test(inner)) {
          files.push({ name: `${entry}/${inner}`, text: readFileSync(file, "utf8") });
        }
      }
    } else {
      files.push({ name: entry, text: readFileSync(path, "utf8") });
    }
  }
  return files;
}

/** The crates the shipped programs run on, with the project's own left out. */
function crates() {
  const metadata = JSON.parse(
    execFileSync(
      "cargo",
      ["metadata", "--format-version", "1", "--locked", "--filter-platform", target],
      { cwd: root, encoding: "utf8", maxBuffer: 1 << 28 },
    ),
  );
  const packages = new Map(metadata.packages.map((each) => [each.id, each]));
  const nodes = new Map(metadata.resolve.nodes.map((each) => [each.id, each]));
  const todo = metadata.workspace_members.filter((id) => shipped.includes(packages.get(id).name));
  if (todo.length !== shipped.length) {
    throw new Error(`the workspace does not have all of: ${shipped.join(", ")}`);
  }
  const version = packages.get(todo[0]).version;
  const seen = new Set();
  while (todo.length > 0) {
    const id = todo.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const dependency of nodes.get(id).deps) {
      // What a program needs to run. What builds or tests it is not in it.
      if (dependency.dep_kinds.some((kind) => kind.kind === null)) todo.push(dependency.pkg);
    }
  }
  const found = [];
  for (const id of seen) {
    const each = packages.get(id);
    if (each.source === null) continue;
    found.push({
      name: each.name,
      version: each.version,
      licence: each.license ?? null,
      home: each.repository ?? each.homepage ?? `https://crates.io/crates/${each.name}`,
      files: licenceFiles(dirname(each.manifest_path)),
    });
  }
  return { version, crates: sorted(found) };
}

/** The package a module of the bundle comes from, as its folder; nothing
 *  for the app's own modules and those the bundler makes up. */
function packageFolder(module) {
  const marker = "/node_modules/";
  const path = module.split("?")[0];
  const at = path.lastIndexOf(marker);
  if (at < 0 || path.startsWith("\0")) return null;
  const parts = path.slice(at + marker.length).split("/");
  const name = parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
  return path.slice(0, at + marker.length) + name;
}

/** The packages whose code is in the window. */
async function packages() {
  const modules = new Set();
  // Vite as the app has it installed, asked to build without writing.
  const vite = JSON.parse(readFileSync(join(app, "node_modules/vite/package.json"), "utf8"));
  const { build } = await import(
    pathToFileURL(join(app, "node_modules/vite", vite.exports["."])).href
  );
  process.chdir(app);
  await build({
    root: app,
    logLevel: "error",
    build: { write: false },
    plugins: [
      {
        name: "modules-of-the-bundle",
        generateBundle(_, bundle) {
          for (const chunk of Object.values(bundle)) {
            for (const id of chunk.moduleIds ?? Object.keys(chunk.modules ?? {})) modules.add(id);
          }
        },
      },
    ],
  });
  process.chdir(root);
  if (modules.size === 0) throw new Error("the bundler named no modules of the bundle");

  const folders = new Set();
  for (const module of modules) {
    const folder = packageFolder(module);
    if (folder) folders.add(folder);
  }
  // Style sheets are not modules of the bundle; what the app's own sheet
  // imports by a package's name is in it all the same.
  const sheet = readFileSync(join(app, "src/index.css"), "utf8");
  for (const [, imported] of sheet.matchAll(/@import\s+["']([^"'./][^"']*)["']/g)) {
    const parts = imported.split("/");
    const name = imported.startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
    folders.add(join(app, "node_modules", name));
  }

  const found = [];
  for (const folder of folders) {
    const manifest = join(folder, "package.json");
    if (!existsSync(manifest)) throw new Error(`no package.json in ${folder}`);
    const each = JSON.parse(readFileSync(manifest, "utf8"));
    const repository = typeof each.repository === "string" ? each.repository : each.repository?.url;
    found.push({
      name: each.name,
      version: each.version,
      licence: typeof each.license === "string" ? each.license : (each.license?.type ?? null),
      home:
        repository?.replace(/^git\+/, "").replace(/\.git$/, "") ??
        each.homepage ??
        `https://www.npmjs.com/package/${each.name}`,
      files: licenceFiles(folder),
    });
  }
  return sorted(found);
}

function sorted(list) {
  return list.sort(
    (a, b) => a.name.localeCompare(b.name, "en") || a.version.localeCompare(b.version, "en"),
  );
}

/** Lines of at most 76 characters, the later ones indented. */
function wrapped(words, indent) {
  const lines = [];
  let line = "";
  for (const word of words) {
    if (line !== "" && line.length + 1 + word.length > 76) {
      lines.push(line);
      line = indent + word;
    } else {
      line = line === "" ? word : `${line} ${word}`;
    }
  }
  if (line !== "") lines.push(line);
  return lines.join("\n");
}

const { version, crates: rust } = crates();
const script = await packages();

// One text is printed once, however many packages carry it: most of them
// carry the same few. Texts that differ only in how they are spaced count
// as one.
const texts = new Map();
for (const each of [...rust, ...script]) {
  each.texts = [];
  for (const file of each.files) {
    const key = createHash("sha256").update(file.text.replace(/\s+/g, " ").trim()).digest("hex");
    if (!texts.has(key)) texts.set(key, { number: texts.size + 1, text: file.text, from: [] });
    const text = texts.get(key);
    text.from.push(`${each.name} ${each.version}`);
    if (!each.texts.includes(text.number)) each.texts.push(text.number);
  }
}

function listed(title, list) {
  const lines = [`${title} (${list.length})`, "-".repeat(`${title} (${list.length})`.length), ""];
  for (const each of list) {
    lines.push(`${each.name} ${each.version}`);
    lines.push(`    Licence: ${each.licence ?? "stated in its licence file"}`);
    lines.push(`    From:    ${each.home}`);
    lines.push(
      each.texts.length > 0
        ? `    Text:    ${each.texts.map((number) => `[${number}]`).join(" ")}`
        : "    Text:    none comes with the package; the licence named above applies",
    );
    lines.push("");
  }
  return lines;
}

const heading = "Third-party software in CA for YubiKey";
const lines = [
  heading,
  "=".repeat(heading.length),
  "",
  wrapped(
    `CA for YubiKey ${version} is free software under the GNU General Public License, version 3 or, at your option, any later version. Its own licence is in the file LICENSE, and its source code is where you got the app from.`.split(
      " ",
    ),
    "",
  ),
  "",
  wrapped(
    "The app and the yca command are built from the software listed here, which comes under licences of its own. Each entry names the licence, where the software is from, and the numbers of the texts that came with it; the texts follow the lists.".split(
      " ",
    ),
    "",
  ),
  "",
  "",
  ...listed("Rust crates", rust),
  "",
  ...listed("JavaScript packages", script),
  "",
  "Licence texts",
  "-------------",
];
for (const text of texts.values()) {
  lines.push(
    "",
    "",
    "=".repeat(76),
    wrapped([`[${text.number}]`, "comes", "with:", ...commas(text.from)], "    "),
  );
  lines.push("=".repeat(76), "", text.text.replace(/\r\n/g, "\n").trimEnd());
}

function commas(names) {
  // A name and its version stay together on a line.
  return names.map((name, at) => name.replace(" ", " ") + (at < names.length - 1 ? "," : ""));
}

mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, lines.join("\n").replaceAll(" ", " ") + "\n");

const bare = [...rust, ...script].filter((each) => each.texts.length === 0);
console.log(
  `${relative(process.cwd(), output)}: ${rust.length} Rust crates, ${script.length} JavaScript packages, ${texts.size} licence texts`,
);
if (bare.length > 0) {
  console.log(
    wrapped(
      [
        `${bare.length}`,
        "come",
        "without",
        "a",
        "licence",
        "file",
        "and",
        "are",
        "listed",
        "by",
        "the",
        "licence",
        "they",
        "name:",
        ...commas(bare.map((each) => `${each.name} ${each.version}`)),
      ],
      "    ",
    ).replaceAll(" ", " "),
  );
}
