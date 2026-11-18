CA WORKSPACE

This folder was made by yca, the "CA for YubiKey" app. It is the workspace
of one certificate authority whose keys live on YubiKeys: everything the
app keeps on the computer for that authority is in here, and nothing of
it is anywhere else.


What is in here

  certificates/           One folder for every certificate you issued,
                          named after it. In it are the files to install
                          on the device, in the form its upload form asks
                          for, and nothing else: the certificate, and the
                          private key that goes with it if the app made
                          that key. The app can write them again in
                          another form. Certificates you sorted into a
                          group are in a folder named after the group.
  register/               The app's own copy of every certificate, named
                          by serial number. It reads these, so the files
                          under certificates/ are yours to take.
  root.pem, issuing.pem   The certificates of your root CA and issuing CA.
                          An authority kept on a single YubiKey has only
                          the root CA, which then signs everything itself.
  The .crt file           The root CA certificate once more, named after
                          your CA: the file to install on every computer
                          and phone that is to trust your certificates.
                          The app has the steps, in the menu of the root
                          CA.
  crl/                    The current revocation list of each CA, once it
                          signed one: the file devices need in order to
                          refuse a revoked certificate.
  index.toml              The list of the certificates: who each one is
                          for, when it expires and whether it is revoked.
  ca.toml                 Which YubiKey holds which CA.
  attestation/            The YubiKeys' proof that the CA keys were made
                          inside them, where they can give one.
  retired/                An issuing CA that was replaced. Certificates it
                          issued stay valid and still need it.
  .lock                   An empty file the app holds on to while it
                          changes the workspace, so that two programs
                          never change it at the same moment.


What about private keys

  The keys of the CAs are not in here and never were. They were made
  inside the YubiKeys, which do not give them out.

  The private keys of certificates you issued are in here, each in the
  folder of its certificate (private-key.key, or inside the .p12 file).
  Whoever reads this folder can pose as those devices and users, until
  you revoke their certificates. They cannot issue anything in your name.

  A device that made its own key and sent a request has no key in here.


Should it be backed up?

  Yes, and with the care the keys in it deserve: an encrypted backup, or
  a disk only you can read.

  If the folder is lost, the CAs still work and every certificate already
  issued stays valid: connect the YubiKeys and start again from them. What
  is gone is the list of what was issued, which is what you need to revoke
  a certificate or to see what expires when, and the files of the
  certificates, which the devices have anyway.


Can it live in iCloud Drive, OneDrive, Google Drive or Dropbox?

  It can, but think twice: the private keys in it would then be in that
  account too, and readable on every device signed in to it.

  Work with it from one computer at a time. Two computers writing at once
  leave conflicting copies behind.

  Keep it downloaded to this computer. If the cloud service removes the
  local copies to save space, the app cannot open the folder offline.

  The app trusts what it finds here. Whoever can change files in your
  cloud account could swap the root certificate you hand out to your
  devices, or hide that a certificate was revoked.

  A synced folder is not a backup: a mistake is copied to every device
  just as faithfully. Keep a real backup as well.


Deleting

  Deleting a certificate in the app deletes its folder here, the private
  key included. Deleting this whole folder removes the authority from
  this computer; the CAs on the YubiKeys are not touched.


One thing to avoid

  Do not edit index.toml and ca.toml by hand; the app expects them as it
  wrote them.
