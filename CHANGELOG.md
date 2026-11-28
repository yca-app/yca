# Changelog

What changed in each release, written for the people who use the app. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.0.2 (2026-11-28)

The app is the same as in 1.0.1. This release exists so that the update from 1.0.1, the first version that updates itself, can be tried on a real release.

## 1.0.1 (2026-11-28)

### Added

- **The app updates itself.** It looks for a newer release when it starts, at most once a day, and says so in its window. Nothing is downloaded until you say so: Update… shows what changed, and Install and restart downloads the new version, checks its signature and puts it in place of the old one. A download can be cancelled, and gives up by itself if it stalls or if more arrives than an update can be. Check for Updates… is in the app's menu, and the dialog has the switch that stops the app from looking by itself. This is the first version that can do it, so it has to be installed over 1.0.0 by hand once more.

### Changed

- **The touch for a new issuing CA is asked for plainly.** The root CA signs a new issuing CA, so it is the root's YubiKey that has to be touched, not the one that is being written to. The wizard now says so as a heading at the moment that YubiKey starts to blink, shows only its serial number, and names it if the touch did not come. The `yca init-issuing` command says it at the same moment.
- **Releases are built by GitHub,** from the public source, by a workflow anyone can read. One machine builds the app and is given no secret. A second one, which builds nothing, signs it with the same Developer ID, has Apple notarise it and leaves a draft, which a person tries with YubiKeys before publishing it.
- **A new CA no longer starts out with a warning about revocation lists.** The window said that a CA "has not signed a revocation list yet" as soon as it had signed anything, which for the root CA was right after the wizard. It now says so only of an issuing CA that took the place of one with a list, which devices may be checking. A CA that has revoked nothing owes nobody a list.

### Fixed

- **A renewal signs what its dialog shows.** Renewing a certificate, or changing its names, took the names, what the certificate is for and the key from the workspace folder at the moment the YubiKey signed, not from what the dialog had shown. A program that wrote to the folder in between could have had other names or a key of its own certified. The app now signs only what was shown, and has the CA on the YubiKey confirm that the certificate it issues again is one this CA issued. `yca reissue` checks the same.
- **The last screen before the PIN names what gets signed.** For a change of names it showed the names the certificate had, not the ones it gets.
- **Nothing is signed with another CA than the one that was shown.** If another program gives the workspace a different CA while a dialog is open, the dialog now says so and asks for no PIN.
- **A certificate and its files are entered in one step,** so that another program working on the same workspace never finds the one without the other. A certificate that was revoked while its renewal was open is no longer issued again, and the certificate a renewal replaces is marked as revoked only once the new one is there in full.
- **Deleting a certificate no longer takes another one's private key.** If the folder of a certificate was moved away or deleted by hand and its entry was left in the list, the next certificate of the same name was given that folder's name. Deleting the old entry then deleted the files of the new certificate, its private key among them. A folder that the list names is now never given out again, whether it is on the disk or not.
- **Files in another form** are refused for a certificate whose private key in the folder is not its own, instead of writing the two out together.
- **Nothing leads what yca writes or deletes out of the workspace folder.** The app and the command move, write and delete files by what the register in the workspace says, and the register is a file that other programs can write to. A serial number in it that was really a path, or a link put where a folder or a temporary file is expected, could have led a deletion, or a private key on its way to its file, out of the workspace. The register is now checked every time it is read, a folder is followed to where it really is before anything is written into it or removed from it, and temporary files are made anew instead of opened.
- **Taking over a CA no longer replaces an issuing CA.** `yca adopt`, and the tool an agent has for it, put whichever issuing CA was connected in place of the workspace's own, with no PIN, no touch and no question, even one that the root CA had revoked. They now add an issuing CA only where the workspace has none. `yca adopt --replace-issuing` does it when a person says so, and an agent cannot. An issuing CA that was replaced is not put back by anything.
- **`yca reset` and `yca delete` ask a person.** The reset took its confirmation, the serial number, from standard input, where a program can put it, and `yca delete` removed a certificate and its private key without asking at all. Both now say what goes and ask at the terminal itself, as a PIN is asked for; where there is no terminal, or with `--json`, they do nothing. An agent asks for a deletion through `yca mcp`, which puts it to you in the app's window.
- **A YubiKey with firmware older than 5.3 gets no CA.** Such a YubiKey does not say whether its CA slot holds a key or whether its PIN is still the factory one, and the app read no answer as an empty slot and a PIN of your own. The wizard made a CA on it, over whatever was there and without the question it otherwise asks, and the app then refused to sign with it. The wizard no longer offers such a YubiKey, the app and `yca` refuse to write to it or to take a CA over from it, and the lists say why.
- **A YubiKey gets no CA while its PUK or management key is the factory one.** The app refused a factory PIN and looked no further. A YubiKey whose PIN had been changed by another tool, or set anew with the factory PUK, kept the PUK every YubiKey ships with, and whoever got hold of it could set a new PIN with that PUK and sign. The app and `yca` now refuse such a key for a new CA, say so wherever it is listed, and put it right: A PUK of your own… in the key's menu, or `yca protect`, which until now said there was nothing to do.
- **A CA from another tool is shown for what it is.** The app makes a CA key inside the YubiKey and has it ask for a touch with every signature. A CA that was taken over keeps the key another tool made, which may sign with the PIN alone, and the app still said that nothing is signed without a touch. It now says, before the CA is taken over and beside it afterwards, if its key does not ask for a touch every time or was put into the YubiKey from outside, and a request from an agent no longer promises a touch that will not be asked for. The README and the security policy say the same.
- **A new issuing CA takes the place of the one the wizard showed, and of no other.** If another program gave the workspace a different issuing CA while the wizard was open, the wizard replaced that one, and with "its YubiKey was stolen" ticked had the root CA revoke it, while its last screen named the CA it had shown. It now says that the workspace has changed, and replaces and revokes nothing. `yca init-issuing --store` and `yca adopt` hold to the issuing CA the workspace had when they were started in the same way.
- **The window stays on the workspace that was opened last.** A change in the workspace it showed before, noticed within the same second, could bring that one back in place of the one just opened.
- **The window does not miss the end of a change made elsewhere.** It looks at the workspace again when the register is written. A change writes other files after that, the files of a new certificate or a revocation list for example, and a look that came between them was not followed by another: the window could go on showing a certificate without its files, or a list that was not the latest.
- **A workspace is started by one program at a time.** Two that started one in the same folder at the same moment, two agents for example, could both succeed, and the second wrote its root CA and an empty register over what the first had made. A folder that still holds the register of a workspace but has lost its list of CAs is not given a new workspace either, which would have emptied the register.
- **A revocation list is kept only as the list of the CA that signed it.** If another program replaced the issuing CA while a list was being signed, the list of the old CA was filed as the new one's.
- **What was stopped halfway is finished by doing it again.** Stopped between two writes, by a crash or a full disk, the replacement of an issuing CA could leave the old CA where it could never be revoked, and a revocation list could get a number that another list had.
- **The app and the command line take turns at a YubiKey.** A YubiKey forgets the PIN as soon as anything else talks to it, and the window looks at the keys every few seconds. A signature started in a terminal while the window was open, or in the window while an agent listed the keys, could fail for no reason a person could see, and a new CA could be left without its certificate. Whatever talks to a YubiKey now waits until the other program has finished.
- **A PIN is not tried with the last attempt, wherever it is typed.** Change PIN… in the window sent the current PIN even when one more wrong one would have locked the YubiKey. Everywhere else the attempts were counted before the PIN was typed, so that another program could use one up in between. They are now counted at the moment the PIN is sent.
- **A YubiKey pulled out in the middle of the wizard** left its step empty, and once plugged in again, the step had forgotten what had happened. The step now stays, says which YubiKey to connect, and keeps what was typed.
- **A CA that was not finished can be started again.** If the touch for a new CA did not come, its key stayed on the YubiKey without a certificate. After leaving the step, the wizard then refused that YubiKey with "slot 9c of this YubiKey is already in use" while showing its slot as empty. The window and `yca devices` now show such a key for what it is, and the wizard replaces it once the serial number is typed, as it does with anything else in the slot.
- **Trying a step of the wizard again** no longer asks a second time where the workspace folder goes, or for the PIN and PUK a new YubiKey was already given.

## 1.0.0 (2026-11-18)

The first release, for Macs with Apple silicon and macOS 13.3 or newer.

### Added

- **A CA on YubiKeys.** A wizard creates a root CA on one YubiKey and an issuing CA on a second one, or a root CA alone that signs everything. The private keys are made inside the YubiKeys, in PIV slot 9c, and every signature needs the PIN and a touch.
- **Taking over a CA** that is already on YubiKeys, without writing to them.
- **Certificates by what they are for:** a web server, a VPN gateway, a VPN client, a TLS client. Also signing a device's own request (CSR).
- **Files as the device's upload form asks for them:** `fullchain.crt` with `private-key.key`, or `certificate.crt`, `intermediate-ca.crt` and `private-key.key`, or one password-protected `certificate.p12`. The files of a certificate can be written again in another form without issuing anything.
- **Renewing, changing names, revoking,** and revocation lists (CRL) with a reminder when one is due.
- **Replacing the issuing CA** when its YubiKey is lost or stolen, with the root CA revoking the old one.
- **Groups, filters and sorting** for workspaces with many certificates.
- **Steps for making devices trust the CA** on macOS, Windows, iOS and Android, with the fingerprints to compare.
- **PIN care from the window:** changing a PIN, setting a new one with the PUK, and resetting the PIV application of a YubiKey whose PIN and PUK are both lost.
- **The `yca` command,** for the same work from a terminal, with `--json` output for scripts.
- **Work with AI agents** through `yca mcp`. An agent can read, sort and revoke; whatever needs a signature it hands to the window, where a person types the PIN and touches the key.
