# Typing a value into a ceremony

`enter_value` and `enter_secret` take something a person types and make it
an artifact. The first is for a value the ceremony records: a serial number
read off a device, an address shown on a screen. The second is for a value it
must not: a passphrase, a PIN.

```yaml
read_the_serial:
  action: enter_value
  role: operator
  with:
    message: "Serial number printed on the token"
    format: alphanumeric
    length: 12
  creates: token_serial

unlock_the_escrow_key:
  action: enter_secret
  role: custodian
  with:
    message: "Passphrase for the escrow key"
  creates: escrow_passphrase
```

The two are one implementation under two names, and the name is the claim.
A reviewer reading the definition sees which steps take a secret without
opening each block, `rite script` prints the step as one, and there is no flag
whose absence would put a passphrase in the transcript.

## What each one makes

`enter_value` makes an artifact a later step reads as it reads any other:
`${artifact.token_serial}` in a message, in a `check_value` beside a
parameter, or as a `reads:` input. The transcript carries the value on the
prompt fact, since typing it is evidence. A step with no `creates:` still
records what was typed.

`enter_secret` makes a secret artifact. Echo is off at the prompt, the bytes
are held wiped in memory and dropped with the run, and the transcript records
that a secret was entered at this step and nothing derived from it, not a
digest either: a hash of a low-entropy secret is a guessing oracle for anyone
holding the transcript. The step needs `creates:`, because a secret typed into
a step that holds it nowhere would be asked for and thrown away.

A secret reaches a later step through `reads:`, not through `with:`. A
`with:` value is evaluated into the step's parameters, which is a copy nothing
wipes and which a step may record; a `reads:` input is borrowed from the store
by name. `import_key` reads one as `passphrase`, which is how a private key
that arrives encrypted on sealed media is imported in the room where its
passphrase holder stands, with no decrypted copy on any disk:

```yaml
install_the_escrow_key:
  action: import_key
  backend: openssl
  reads:
    key_material: ${artifact.escrow_key}
    passphrase: ${artifact.escrow_passphrase}
  with:
    algorithm: RSA-4096
  creates: escrow_keypair
```

The import records the name of the passphrase artifact and nothing about its
value. It refuses a passphrase read from anything but a secret artifact, since
a passphrase that sat in a material file is what typing one exists to avoid,
and it refuses a passphrase given for a key that turns out not to be
encrypted: the record says one was supplied, and that has to mean it was used.

As with opened content, what happens next is the author's call, made in the
definition. Declaring a secret artifact under `output:` writes it to the run
directory; an expression exposes what the author asks of it. Rite does not
second-guess either.

## Saying what kind of value it is

Both actions take `format:` and a length, so a slip is refused at the keyboard
rather than found later, and the rule is stated in the prompt before typing.

| `format` | The value is | The artifact is |
| --- | --- | --- |
| `text` (default) | anything typed | the text |
| `digits` | `0` to `9` | the text |
| `alphanumeric` | ASCII letters and digits | the text |
| `hex` | bytes, two digits per byte, either case | the decoded bytes |
| `base64` | bytes, standard base64 with padding | the decoded bytes |
| `{ pattern: "..." }` | whatever the regular expression accepts, in full | the text |

Each format has one canonical representation, and that is what the step
keeps. For text formats it is the text as typed. For an encoding it is the
bytes: the string was transport, and its grouping and case are dropped on the
way in, so a key component typed as `DE AD BE EF` and one typed as `deadbeef`
make the same artifact. What was typed is still on the prompt fact of an
`enter_value` step, since that is the evidence; the artifact is what the
ceremony uses. A pattern is anchored at both ends, so `[0-9]+` accepts `1234`
and not `abc1234`.

`length`, or `min_length` and `max_length`, bound the value in the format's
own unit: characters for text, bytes for an encoding. `format: hex` with
`length: 32` asks for a 32-byte key, however it is grouped.

```yaml
enter_the_component:
  action: enter_secret
  role: custodian
  with:
    message: "Your component of the transport key"
    format: hex
    length: 32
  creates: kek_component
```

`length` and the bounds are exclusive, and a pattern takes no length, because
a value described twice is a rule the author would have to guess the
combination of. `rite check` reports either, a format outside the vocabulary,
and a pattern that does not compile.

Nothing given asks only for a non-empty value. A refusal at the prompt names
the rule and never what was typed, so a secret that missed its shape is not
echoed back by the message that refused it.

The rule is part of the prompt, so it is recorded with it: the transcript says
a six-digit secret was entered, which is what the definition already said.

Encodings with a checksum and a wordlist, `bech32m` and `bip39`, are not in
the vocabulary yet. They follow the same rule when they land: one canonical
form each, which for a BIP-39 phrase is the normalized words rather than the
entropy, since that is what a wallet takes.

## Dry runs

A dry run has no person at the keyboard. The headless driver answers an
unconstrained prompt with a fixed placeholder and a formatted one with a
placeholder of that format at its shortest length, so a rehearsal walks
through a PIN or a passphrase step as it walks through any other. A pattern
cannot be answered generically, and a step carrying one fails fast in a dry
run rather than being refused and asked again without end.

The placeholder is never the real passphrase, so an `import_key` that needs
one fails in a dry run.

## A wrong value found later

A rule catches a slip in shape, not in substance. A passphrase that is the
wrong passphrase passes `enter_secret` and fails `import_key` three steps
later, and a retry of the import re-reads the same artifact. Today the way
out is to abort and start again. Re-entering the value from the failed step
is a change to the execution model, recorded as a design question rather
than done here.
