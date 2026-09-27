# Demo outputs

Sample outputs of the showcase ceremony, [`examples/showcase/demo.rite.yaml`](../../examples/showcase/demo.rite.yaml):
a root signing key generated, certified and exported, with a crypto officer and a witness.

| File | What it is |
|---|---|
| [`demo-script.html`](demo-script.html) | The printed protocol, from `rite script`, that participants follow and complete by hand. |
| [`demo.gif`](demo.gif) | The ceremony run with `rite run`. |
| [`demo-bundle/`](demo-bundle/) | The evidence bundle of one run, from `rite bundle create`: the complete transcript, the ceremony definition it ran from, and the artifacts. |
| [`demo-report.html`](demo-report.html) | The report of that run, from `rite report`. |
| [`demo-disclosure/`](demo-disclosure/) | The public disclosure of the same run, from `rite bundle disclose --level public`. Every fact above public is withheld, and the definition is left out. |
| [`demo-disclosure-report.html`](demo-disclosure-report.html) | The report of the disclosure: what the public sees, stated as such. |

The bundle and the disclosure have the same transcript fingerprint. Both verify from a clone:

```sh
rite verify docs/demo/demo-bundle
rite verify docs/demo/demo-disclosure
```

Comparing the two transcripts line by line shows what a disclosure keeps. A withheld line keeps its time, its level
and its two checkpoints, so the chain still folds to the same fingerprint, and drops its salt and its fact. The names of
the crypto officer and the witness are in the bundle, and not in the disclosure.

## Regenerating

`render-prints.sh` produces every file here except the GIF, from one run, and `record.sh` records the GIF. See each
script for when to run it.
