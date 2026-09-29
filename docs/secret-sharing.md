# Secret sharing

`split_secret` turns a secret into shares, of which a chosen number put it
back together. `reveal` shows a share for its custodian to write down.
`combine_shares` rebuilds the secret from the shares that come back. Any
two of three custodians, say, can recover a wallet's recovery phrase; one
alone learns nothing.

```yaml
split_the_seed:
  action: split_secret
  backend: openssl
  reads:
    secret: ${artifact.seed}
  with:
    threshold: 2
    shares: 3
  creates: shares

hand_over_share_1:
  action: reveal
  role: custodian_1
  reads:
    value: ${artifact.shares.share_1}
  with:
    message: "Share 1, for the first custodian's envelope"
    length: 32

recover_the_seed:
  action: combine_shares
  reads:
    shares:
      - ${artifact.shares.share_3}
      - ${artifact.shares.share_1}
  creates: recovered_seed
```

`secret` is any artifact that resolves to bytes: a material carried into the
room, or a secret a person typed into an earlier step. `threshold` is how
many shares recover the secret and `shares` how many are made, each from 2
to 100, with at least as many shares as the threshold.

## What a split does before it finishes

Every combination of `threshold` shares is put back together and compared
with the secret before the step completes. A share that leaves the room has
been shown to work with every other one. The check bounds the split: a
shape with more than 100,000 combinations (9-of-20, say) is refused, which
admits any split a room of custodians receives, up to 2-of-100, 3-of-85,
4-of-40, 5-of-26 or 8-of-16. `rite check` does not count combinations; a
dry run does, and a dry run is the way to find out.

The randomness a split needs comes from the step's backend, which is why
`split_secret` names one. A biased draw would leak the secret, so the
backend answers for it the way it answers for a key it generates. The
arithmetic itself is Rite's, in one file meant to be read in full; see
[development/cryptographic-dependencies.md](development/cryptographic-dependencies.md)
for why that is the one primitive not taken from a provider.

## What a share is

A share is three things: how many shares recover the secret, which share
this is (1, 2, 3, and so on), and one value per byte of the secret. The
split creates one artifact holding every share, and a later step names one
as `${artifact.shares.share_2}` under its `reads:`. Nowhere else: a share
never appears in `with:`, in a `description:` or in a message, because an
expression makes a copy the run does not wipe and a message is recorded in
the transcript. A step that shows or combines a share borrows it and gives
it back.

Shares are never written to a file. A file holding every share is the
secret under another name. What leaves the machine is one share at a time,
on paper, through `reveal`.

## Showing a share

`reveal` shows a value in a window of its own, once. The window first says
the value is coming, with the step's `note:`, and shows it when the person
presses Enter. Enter again asks whether every row is written down
and checked, since it is not shown again; only a yes closes the window and
takes the value off the screen. In a plain console the value stays in the
terminal, and the person is told to clear it. The transcript records that
the value was shown and nothing of what it was. `message` says what the
value is and what to do with it, and is the window's title and the sheet's
heading.

A share is shown as rows of characters, 28 of data and 4 of parity each,
the last row shorter. The alphabet is digits and letters without `I`,
`L`, `O` and `U`, in either case, and when a share is typed back an `O`
reads as `0`, an `I` or `L` as `1`, and a `U` as a character that could not
be read. A 32-byte secret is two rows of 32.
The parity is Reed-Solomon over the row: one wrong character in a row is
corrected and the row named, so the person checks it against the sheet;
up to two characters the person cannot read, typed as `?`, are recovered;
a row that needs more is refused by name, to be read again from the sheet
rather than guessed at. The encoding is called paper32.

`reveal` shows any byte artifact, not only a share, in the same rows;
`format: hex` shows either as two characters per byte instead.

`rite script` prints a sheet for every `reveal` step, one page each, in a
document of its own beside the script, `<name>.worksheets.html`, since a
sheet is printed once and kept with the value while the script is copied
for everyone in the room: rows of boxes in groups of four with the parity
cells shaded at the end of each row, the encoding named in small print and
the step's `note:` beneath the heading. Give `length:` (the value's size
in bytes, and for a share the secret's, as on `enter_share`) and the sheet
has exactly the right rows, and the step refuses a value of another size
before showing it; leave it out and the sheet has five rows to use as
needed.

A dry run walks a `reveal` step. A real run without a screen, under
`--frontend headless`, stops at it: no one is there to write, and printing
a secret to a log serves nobody.

## Typing a share back

`enter_share` asks for a share from its sheet, one row at a time, and
creates a share artifact that `combine_shares` reads:

```yaml
type_share_back:
  action: enter_share
  with:
    message: "Recovery share 3"
    length: 32
  creates: share_from_bag_3
```

Each row is checked as it is typed. A wrong character is corrected and
the row named, so the person checks that character on the sheet; up to
two characters the person cannot read, typed as `?`, are recovered; a row
that needs more is typed again. Case, spaces and dashes do not matter.
When all the rows are in, rows that are not a share, from a different
sheet say, are refused and asked for again.

`message` is required and says which sheet. `note:` is shown with the
rows. `length:` is the secret's length in bytes, as on the `reveal` step
that wrote the sheet: the prompt then asks for exactly the right rows, and
a share of another size is refused. Every row but the last is full, so a
short row is the last one; without `length:`, it ends the entry, and so
does an empty row after full ones. `format: hex` reads a sheet written in
hex.

What is typed is never written to the transcript. The step records which
share came back, by its index, and which rows needed a repair.

A run without a screen stops at the step, in a dry run as well: the rows
are on a sheet only a person holds.

## Putting the secret back

`combine_shares` takes its shares as a list, at least two, in any order:
shares an earlier step made in the same run, or shares custodians typed
back, each its own artifact. Each share knows how many are needed, so too
few is refused before anything is computed, and shares that disagree with
each other on that count or on the secret's length are refused as well.

That is all the shares can say. Two shares from different splits of the
same shape combine into a wrong secret without complaint. A recovery
therefore ends by checking what came back against something it can see:
an address the wallet shows once the phrase is restored, a check value a
token prints, a `check_value` against a known digest in a drill.

The recovered secret stays in memory and is dropped with the run, like
content `decrypt_data` opens.

## What the transcript says

For a split: the scheme, the threshold and the count, which artifact was
split, which backend supplied the randomness, and how many combinations
were checked. For a recovery: the scheme, the threshold, and which share
indexes went in. For a `reveal`: the message and the acknowledgement.
For an `enter_share`: the message, the share's index and threshold, and
the rows that were repaired.
Never a share, never the secret, not a digest of either and not the
secret's length, which is its shape and, for a passphrase, its character
count.

## The scheme

The scheme is named `rite-sss/v1` in the transcript so a recovery decades
from now knows what it is looking at. It is Shamir's secret sharing over
GF(2⁸) with the AES polynomial, one polynomial per byte of the secret,
shares evaluated at 1, 2, 3 and so on, and the secret at 0. That is the
construction of [draft-mcgrew-tss-03](https://datatracker.ietf.org/doc/html/draft-mcgrew-tss-03)
and of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md),
and the field arithmetic of [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final)
section 4.2; Rite's shares combine with any GF(256) implementation of it,
and the test suite checks the draft's vector and a split computed with
SLIP-0039's reference implementation.

A share on paper is the share's bytes, `[version 1][threshold][index]`
followed by the per-byte values, as paper32: five bits per character in
the order `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, rows of 28 characters each
followed by 4 of parity, the parity being the row's polynomial (through
its data at the field elements 0 to 27 of GF(32) with x⁵ + x² + 1)
evaluated at the elements 28 to 31. Decoding a correct sheet without Rite
needs none of that: drop the last four characters of each row, read the
rest as base 32, drop the first byte, read the threshold and index, hand
the rest to the arithmetic above.
