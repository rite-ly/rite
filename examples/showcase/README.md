# Showcase Ceremonies

These ceremonies exist to **demonstrate Rite's features**: roles and abbreviations,
acts and sections, prerequisites, physical and digital materials, structured
step instructions (paragraphs and bullet lists), generated outputs, and
post-ceremony duties. They render well as printed scripts and run end to end with
the OpenSSL backend.

> **Not real ceremonies.** The roles, names, parameters, and key material here are
> illustrative. Do not copy these as-is for an actual key ceremony.

All ceremonies in this directory are runnable with no external setup.

## Ceremonies

### `demo.rite.yaml` — Root Signing Key Ceremony

A compact, single-page ceremony: environment check, ECDSA-P256 keypair generation,
self-signed certificate issuance, and witness attestation. This is the ceremony used
in the project demo recording.

### `offline_backup.rite.yaml` — Offline Backup Key Ceremony

A deliberately maximalist ceremony spanning four acts, four roles, physical and
digital materials, and long structured step instructions. It generates a
backup-wrapping key, escrows it under the bundled test key, and hands sealed media
to a custodian. Use it to see how a dense, formal script renders across pages.
