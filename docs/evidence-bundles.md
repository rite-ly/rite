# Evidence bundles

A run leaves a directory: the transcript and the artifacts the ceremony wrote. An evidence
bundle packages that record for keeping or for handing to someone else, with the ceremony
definition it ran from. A disclosure is a bundle with part of the record withheld, for a wider
audience.

A bundle and every disclosure made from it verify to the same transcript fingerprint, the one
written on paper at the end of the ceremony.

## Creating a bundle

```sh
rite bundle create root-ca-20260926T101500 --definition root-ca.rite.yaml -o root-ca-bundle
```

`rite bundle create` copies the transcript, the definition and the artifacts into a new
directory, and checks each file on the way in:

- the transcript must verify, withhold nothing, and end with `ceremony_completed` or
  `ceremony_failed` (`--allow-truncated` accepts an interrupted run);
- the definition must match the digest `ceremony_started` records; `--without-definition` leaves
  it out on purpose;
- each artifact must match the digest its `artifact_written` fact records.

Opened content (decrypted data, recovered secrets) is never bundled. An artifact missing from the
run directory is left out. The output names both. If a check fails, the command removes the
partial bundle. Only the file owner can read the files it writes.

## Layout

```text
root-ca-bundle/
  bundle.json                    the index
  transcript.jsonl
  definition/ceremony.rite.yaml
  artifacts/root_cert.pem
  artifacts/root_public_key.pem
```

A bundle is a directory. To send one, archive it with any tool, and verify the extracted
directory.

`bundle.json` lists each file with its role and names the transcript fingerprint:

```json
{
  "$schema": "https://ritely.io/schemas/0.6.0/bundle.schema.json",
  "rite_bundle": 0,
  "kind": "complete",
  "fingerprint": "sha256:…",
  "files": [
    { "path": "transcript.jsonl", "role": "transcript" },
    { "path": "definition/ceremony.rite.yaml", "role": "definition" },
    { "path": "artifacts/root_cert.pem", "role": "artifact", "name": "root_cert" }
  ]
}
```

The index holds no digests. The transcript already records a digest for every file the index
lists, so the index needs no protection of its own. `rite verify` checks it against the files and
the transcript.

## Disclosing part of it

```sh
rite bundle disclose root-ca-bundle --level public -o root-ca-public
```

Every fact is recorded at a confidentiality level (see
[the transcript format](transcript-format.md#confidentiality-levels)). `rite bundle disclose`
keeps the facts at or below the level you give, by name or by number, and withholds the rest. A
withheld line keeps its commitment, so the disclosure verifies to the same fingerprint as the
complete bundle.

A disclosure carries an artifact only when the fact that recorded it is disclosed. It never
carries the ceremony definition, which can name people and parameter values. Its index says
`"kind": "disclosure"` and gives the `threshold`.

## Verifying

```sh
rite verify root-ca-bundle
rite verify root-ca-public
```

On a bundle, `rite verify` checks the transcript as it does for a run. Then it checks the index:
the fingerprint it names, every file it lists, the definition against its digest, and each
artifact against its digest. A file the index does not list is named but not checked.

For a disclosure, `rite verify` also checks the threshold. Verification fails if a line at or
below the threshold is withheld, if a line above it is disclosed, or if the bundle holds the
definition.

Then compare the printed fingerprint with the one written on paper (see
[what `rite verify` proves](transcript-format.md#what-rite-verify-proves)).
