# JSON Schemas

JSON Schemas (draft 2020-12) for the files `rite` writes, so other tools can check them without Rust:

- [`transcript.schema.json`](transcript.schema.json): one line of `transcript.jsonl`. The first line is the header; every
  other line is a fact, complete or withheld.
- [`bundle.schema.json`](bundle.schema.json): the `bundle.json` index of an evidence bundle.

What the files mean, and how the chain is computed, is in [the transcript format](../transcript-format.md) and
[evidence bundles](../evidence-bundles.md).

Each schema describes one format version, pinned in the header's `rite_transcript` and `vocabulary`, and in the index's
`rite_bundle`. Integers are bounded to `±(2^53 - 1)`, the range the transcript's canonical form writes.

## Versions and URLs

Before 1.0 the three version numbers are 0 and the formats change between releases without a new number. Each release
publishes its schemas at a URL of its own, which is each schema's `$id`:

```text
https://ritely.io/schemas/<release>/transcript.schema.json
https://ritely.io/schemas/<release>/bundle.schema.json
```

A published schema never changes, so a transcript is checked against the schema of the release that wrote it. `rite`
writes that URL as `$schema` at the top of `bundle.json`, which editors read to validate the index, and on the first line
of `transcript.jsonl`, outside the committed header. Editors do not apply a schema to each line of a JSON Lines file, so
for the transcript the URL is for tools that read it.

A schema checks the shape of a file, not its integrity. It does not recompute a line's `leaf` or `chain`, check that a
fact is in canonical form, check that each level is declared in the header, or check a disclosure against its threshold.
`rite verify` checks those.

The transcript schema lists the fact types of its vocabulary and refuses any other. A reader of the transcript format
accepts a fact type from a newer vocabulary and counts it as unknown; a tool that wants the same behaviour checks the
header's `vocabulary` before validating the facts.

## Regenerating

The schemas are generated from the Rust types that read and write the files, by the tests of `rite-model`, and a test
fails when the committed files differ.

The descriptions are not the Rust doc comments. They are written for readers of the files, as a
`schemars(description = "...")` attribute on each type, variant and field, so editing the code's documentation never
changes a schema. An item without one falls back to its doc comment, so a new fact or field needs one.

After a change to those types or descriptions:

```sh
RITE_UPDATE_SCHEMA=1 cargo test -p rite-model schema
```
