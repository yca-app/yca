# Contributing

Thank you for wanting to help. The project is young and its design is still moving, so for anything larger than a fix, please open an issue first and say what you have in mind.

## Before you send a change

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
npm --prefix app run build
```

A few things the code holds to:

- **Decisions live in `yca-core`.** The command line and the window only translate. Whatever the window can do, the core can do without it, and a test without a YubiKey covers it.
- **Nothing is written to a YubiKey beyond what a CA needs:** PIV slot 9c, the PIN, PUK and management key of a key in its factory state, and a PIN on request. No other slots, no other applications on the key. The reset of the PIV application is the one exception, and stays a command of its own that asks for the serial number.
- **No private key of a CA ever exists outside its YubiKey.** The private key of a certificate the app made the key for lives in that certificate's folder in the workspace, and nowhere else.
- **No PIN, PUK or password ever goes to a program.** What needs one is handed to the app's window, where a person types it. Nothing in the command line's JSON, the MCP server or the app's socket takes a secret.
- **One description for everyone.** What a workspace, a certificate and a YubiKey look like from outside is in `yca_core::view`, and the window, `--json` and the MCP server hand out exactly that.
- **One CA, one workspace.** Whatever the app keeps for a CA goes into its workspace folder, never beside it.
- **The interface is in English and speaks of what the user wants,** not of PKI. All of its words are in `app/src/lib/text.ts`.
- **It names neither makes nor kinds of device.** Where it asks how a device takes a certificate, it asks what the upload form looks like, which the user can see, not what the device is. A certificate's folder then holds the files of that form and nothing else.
- **Sizes are those of macOS, in whole pixels.** Text comes in the sizes of the type scale and nothing else: 13 px for whatever is read or clicked, 11 px only for what is secondary to something larger (a caption over a value, a second line, a hint under a field, a tag), 15 px for the name of a CA in the sidebar, 17 px for headings. They are the same on every screen. No height, width, padding or gap may come out at a fraction of a pixel. Both are kept in one place, the theme in `app/src/index.css`: the spacing steps that would land between pixels are moved onto whole ones there. If you use a step that is not there and not even, add it.
- Comments say why, in plain sentences.

If your change writes to a YubiKey, say in the pull request whether you tried it on hardware, and on which firmware.

## Contributor agreement

The project is published under the GNU General Public License, version 3 or later. So that the project as a whole can also be offered under other terms later, contributions are accepted under the following agreement. By sending a contribution you agree to it.

1. **It is yours to give.** You wrote the contribution yourself, or you have the right to submit it under these terms. If your employer has rights in what you write, you have its permission.
2. **You keep your copyright.** Nothing here transfers ownership of your contribution.
3. **You license it to everyone** under the GNU General Public License, version 3 or, at the recipient's option, any later version.
4. **You also license it to the maintainer of the project,** without charge and for good, to use, copy, change and distribute your contribution as part of the project under any licence terms, including terms other than the GNU General Public License, and to let others do the same.
5. **You give no warranty,** and you are not obliged to support your contribution.
