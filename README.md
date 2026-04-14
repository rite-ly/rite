# Rite

A DSL and runtime for cryptographic key ceremonies.

> **Beta** — Rite is under active development. Expect breaking changes.

## Design principles

Rite is early-stage, but a few design principles already shape the project and the direction of the DSL and runtime.

- **Socio-technical by default** *(Status: guiding principle)*  
  Rite treats ceremonies as human protocols with machine assistance, not as programs with a few manual steps around them.  
  The goal is to model roles, attestations, physical actions, and machine checks as parts of the ceremony itself.

- **Evidence over execution** *(Status: guiding principle)*  
  Rite is intended to produce evidence of what was supposed to happen, what actually happened, and where the two diverged.  
  The long-term aim is a system where transcripts, reports, and verification artifacts are derived from the same source rather than maintained separately.

- **Error modes are first-class** *(Status: in progress)*  
  Real ceremonies fail through confusion, omission, and improvised recovery, not just through broken cryptography.  
  Rite aims to make retries, aborts, resumptions, and deviations explicit parts of the model instead of operator folklore.

- **Humans stay in control, but within guardrails** *(Status: guiding principle)*  
  The machine should guide, verify, record, and enforce structure, while humans remain responsible for judgment, observation, and physical actions.  
  The design goal is to make the safe path easy to follow and exceptional paths explicit and reviewable.

- **Small, inspectable core** *(Status: current direction)*  
  High-risk flows justify suspicion of abstraction, so Rite aims for a small and understandable core.  
  The project favors explicit structure, simple execution semantics, and narrow interfaces over hidden behavior or heavy framework magic.

- **Trust boundaries must be explicit** *(Status: guiding principle)*  
  Rite distinguishes machine-verifiable facts, human attestations, and environmental assumptions.  
  A ceremony tool should make clear what it can prove, what participants must witness, and what remains outside the reach of software.

- **One structure, many outputs** *(Status: target architecture)*  
  A single ceremony definition should eventually produce the artifacts teams actually need: guided execution, printable scripts, dry runs, reports, and verification inputs.  
  This is intended to reduce drift between ceremony docs, hand-maintained checklists, shell snippets, and audit records.

- **Reusable templates, explicit inputs** *(Status: current direction)*  
  Ceremonies should be reusable as templates, with run-specific values supplied explicitly rather than leaking in from hidden configuration.  
  Rite aims to make ceremony structure reusable while keeping execution-specific inputs visible and auditable.

- **Usable security is central** *(Status: guiding principle)*  
  A ceremony that people cannot follow correctly under pressure is not operationally secure.  
  Rite aims to improve clarity, pacing, rehearsal, and role-specific guidance so that stronger ceremony structure becomes easier to use, not harder.

- **Open, auditable, and compatible with real infrastructure** *(Status: target architecture)*  
  Rite is intended to earn trust by being inspectable and by fitting the systems teams already use.  
  The long-term goal is an open specification, an auditable implementation, and compatibility with real devices and backend ecosystems rather than an isolated greenfield tool.

## License

Rite is currently licensed under GPLv3.  
We chose GPL as a familiar copyleft license for an early-stage project where we want to keep the core open while retaining flexibility to revisit licensing later.  
The SDK and model crates are expected to move to a more permissive license such as MIT or Apache 2.0 in the future.