# Transcript format

`rite run` records every ceremony in `transcript.jsonl`: one JSON object per line, the header
first, then one line per fact in the order the facts happened. The file is append-only. Each
line is written and synced to storage before the run moves on, so a crash or a power loss leaves
every line recorded until then.

The last `chain` value is the transcript fingerprint. Participants write it on paper at the end
of the ceremony, and anyone can recompute it from the file later. This page describes the format
for anyone writing their own verifier. The JSON Schemas in [`schema/`](schema/README.md) describe
the same lines field by field.

## The header line

```json
{"$schema":"https://ritely.io/schemas/0.6.0/transcript.schema.json","header":{"dry_run":false,"levels":{"confidential":30,"public":10,"restricted":20},"producer":"rite 0.6.0","rite_transcript":0,"run_id":"0ac4d127ee9b2b05447c9d241c3b5b0c","vocabulary":0},"chain":"sha256:…"}
```

| Member | Meaning |
|---|---|
| `header.rite_transcript` | Format version: the line layout and the chain rule. A reader refuses a version it does not know, before reading anything else. |
| `header.vocabulary` | Version of the fact vocabulary. |
| `header.producer` | The program and release that wrote the file, for information only. |
| `header.run_id` | 16 random bytes as hex, to tell runs apart before the fingerprint exists. |
| `header.dry_run` | Whether the run was a rehearsal. A dry run uses a fixed, publicly known entropy seed, so its transcript is not evidence of a real ceremony. |
| `header.levels` | Every confidentiality level the transcript uses, by name. |
| `chain` | `node_0`, the commitment to the header. |
| `$schema` | The JSON Schema of the release that wrote the file, for editors and other tools. The chain does not commit to it, and a reader ignores it. |

## Fact lines

```json
{"at":"2026-09-26T10:40:29.057123Z","level":10,"leaf":"sha256:…","chain":"sha256:…","salt":"<32 hex digits>","fact":{"type":"step_started",…}}
```

| Member | Meaning |
|---|---|
| `at` | When the fact was recorded: RFC 3339, UTC, microseconds. Committed as the exact string on the line. |
| `level` | The fact's confidentiality level, an integer the header names. |
| `leaf` | The commitment to the fact under its salt. |
| `chain` | The chain value after this line. |
| `salt` | 16 random bytes as 32 lowercase hex digits. |
| `fact` | The fact, an object whose `type` names its kind. |

A **withheld** line, in a disclosure, has only `at`, `level`, `leaf` and `chain`. These are enough
to compute the chain, so a transcript with withheld lines has the same fingerprint as the complete
one.

Members may appear in any order; a reader finds them by name. A line has either both `salt` and
`fact` or neither.

## The commitment chain

```text
node_0      = SHA-256(0x02 ‖ JCS(header))
leaf_i      = SHA-256(0x00 ‖ salt_i ‖ JCS(fact_i))
node_i      = SHA-256(0x01 ‖ node_{i-1} ‖ len(at_i) ‖ at_i ‖ level_i ‖ leaf_i)
fingerprint = node_n
```

- `JCS` is the RFC 8785 canonical form of the JSON value: members sorted by their UTF-16 code
  units, no whitespace. Any reader that parses a fact computes the same bytes, whatever the
  member order on the line.
- Facts hold integers only, within `±(2^53 - 1)`, and no other numbers. `rite check` refuses any
  other number in a ceremony before it runs.
- `salt_i` is the 16 decoded bytes, not the hex text.
- `at_i` is the UTF-8 string on the line. `len(at_i)` and `level_i` are 8-byte big-endian
  unsigned integers.
- Each hash input starts with its own byte (`0x00` leaf, `0x01` node, `0x02` header), so no leaf,
  node or header can hash the same input as another.
- `leaf` and `chain` can be recomputed. They are stored so a verifier can name the first line
  where its result differs. A `leaf` mismatch means the fact or its canonical form differs. A
  `chain` mismatch with a matching `leaf` means the time, the level or an earlier line differs.
  Someone who forges a transcript recomputes them too, so they do not detect forgery.
- The `chain` of the last line is the fingerprint. No other file is needed to know it.

Test vectors are in `rite_model::commitment` (the module example, and `construction_vectors`).

Each fact gets a new salt from the operating system's random source. The salt hides a withheld
fact: without it, anyone with the leaf could test guesses of the fact against it. The salt never
comes from the ceremony's entropy source, because that source is public so that `rite verify` can
re-derive it.

## Confidentiality levels

A level is an integer; a higher number is a narrower audience. Three are built in, at fixed
values in every transcript:

| Level | Value | Audience |
|---|---|---|
| `public` | 10 | anyone |
| `restricted` | 20 | auditors, under agreement |
| `confidential` | 30 | the organisation that ran the ceremony |

The header's `levels` table names every level the transcript uses. The built-ins must appear at
their values, no two names share a value, and a reader refuses a line at a level the header does
not name.

The chain includes each line's level, so a disclosure cannot move a fact to another level. Each
fact type has a default level:

| Level | Facts |
|---|---|
| public | `ceremony_started`, `role_declared`, `act_started`, `step_started`, `backend_operation`, `attestation_recorded`, `step_completed`, `ceremony_completed`, `ceremony_failed`, and the entropy facts, which `rite verify` needs to re-derive the entropy |
| restricted | `parameter_bound`, `material_loaded`, `backend_bound`, `prompt_answered`, `wrap_recipient_recorded`, `step_attempt_failed`, `deviation_recorded` |
| confidential | `role_assigned`, `material_digest`, `machine_info_recorded` |

`artifact_written` takes its level from the artifact: certificates, public keys, CSRs and
signatures are public; wrapped keys, ciphertext and other content are restricted; opened content
is confidential.

A secret value (a private key, a PIN, a passphrase, opened plaintext) is never recorded, at any
level.

## Facts

Each fact records one kind of information. Where two values may go to different audiences, such
as a material's name and the digest of its content, they are separate facts. The kinds:

- `ceremony_started` (with the digest of the ceremony definition), `ceremony_completed`,
  `ceremony_failed`
- `role_declared`: each role's id and name
- `role_assigned`, `parameter_bound`, `material_loaded`, `material_digest`: the run's inputs,
  one fact each
- `backend_bound`: a backend's identity, recorded the first time the backend is used
- `act_started`, `step_started`, `step_attempt_failed`, `step_completed`
- `prompt_answered`: the prompt, and the answer unless it is a secret
- `backend_operation`: the kind of operation, the backend the step ran with, and what went in and
  came out
- `attestation_recorded`, `machine_info_recorded`, `wrap_recipient_recorded`
- `entropy_seeded`, `entropy_contributed`, `entropy_drawn`
- `artifact_written`: the file name under `artifacts/`, and its digest unless it is opened
  content
- `deviation_recorded`

The schema lists every field. Digests are written `sha256:` followed by 64 lowercase hex digits.

## What a disclosure shows

A withheld line keeps its time and its level. So a reader of a disclosure sees how many facts
were withheld at each level, and when each one was recorded. For example, four confidential lines
at the start of a run are four people assigned to roles, and the time between two lines shows how long an
answer took. A withheld line's step is known from its position: it sits between that step's
public `step_started` and `step_completed`.

A disclosure shows when the ceremony took place. The public artifacts usually show it too, since
a certificate's validity starts when it was issued.

## Versions

Before 1.0, `rite_transcript` and `vocabulary` are 0, and the format can change between releases
without a new number. `producer` names the release that wrote a transcript. Verify a transcript
with that release. `rite verify` prints a warning when another release wrote the transcript. At
1.0 the numbers become 1 and the format stops changing.

When a reader does not know a fact's type, it still checks the fact against its leaf. It counts
the fact instead of reading it, and `rite verify` reports the count next to its result.

## What `rite verify` proves

`rite verify` accepts a run directory, a transcript file or an evidence bundle. It checks:

- the header, and that every line's `leaf` and `chain` recompute, up to the fingerprint it prints;
- the entropy: every drawn value re-derives from the recorded seed and contributions;
- each artifact present against its recorded digest, and each wrapped key against what the
  transcript says produced it;
- for a bundle, the index, the definition against the digest `ceremony_started` records, and for
  a disclosure, that every line at or below its threshold is disclosed and every line above it
  withheld.

These checks show that the transcript is consistent with itself and with the files next to it.
They do not show that it is the transcript written during the ceremony, because someone who
rewrites the whole file can recompute every value. To check that, compare the fingerprint
`rite verify` prints with the one the participants wrote on paper at the end of the ceremony.
