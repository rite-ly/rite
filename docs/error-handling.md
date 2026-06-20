# Error Handling

Scope: what happens when a step fails during `rite run`, and the `retry:` field.

## When a step fails

A failure is classified by its nature:

- **Transient**: the world was not ready (a token absent, a loose cable, a PIN
  required). The run pauses and prompts the operator to **Retry** or **Abort**.
- **Fatal**: a verification mismatch, a broken definition, or a blocked device.
  The run stops. There is no retry, because re-running a failed verification
  would be tampering, not recovery.

Every failed attempt is recorded in the transcript as a `step_attempt_failed`
event, so a retry is auditable: attempt 1 failed, the operator chose retry,
attempt 2 succeeded.

A step is **never retried once it has produced evidence** (an artifact, a backend
operation, or a drawn random value). After a side effect, re-running is not safe,
so the failure becomes fatal even if its cause was transient.

## Retriability is a property of the failure, not the step

The same action can fail either way depending on what goes wrong, so a step is
not statically "retryable" or "not retryable":

- Steps that touch hardware or the environment (a token, a TPM, a PIN) can hit
  transient failures, and so can prompt for retry.
- Pure-logic and software steps (a `confirm`, a `check_value`, a software-key
  operation) generally fail fatally: their failures are results, not conditions,
  so they are never retried.

You do not need to predict this when authoring. The safe default (prompt on a
transient failure) already applies to every step. The `retry:` field only
**constrains** that default, it never enables retry:

- `retry: never` always takes effect: it forbids the prompt on any step.
- `retry: { attempts: N }` only bites if a transient failure actually occurs; on
  a step that can only fail fatally it is simply inert.
- A fatal failure ignores `retry:` entirely and stops the run. You cannot retry a
  verification until it passes; the classification lives on the error types in
  the runtime, and a ceremony author cannot mark a mismatch retriable.

## Constraining retries: `retry:`

By default a transient failure prompts the operator with no limit. The `retry:`
field constrains that, per step:

```yaml
steps:
  # If the token is absent or a cable is loose, the operator can reseat it and
  # retry, up to a hard cap. Exhausting the cap fails the ceremony.
  import_transport_key:
    action: unwrap_key
    backend: openssl
    retry: { attempts: 3 }

  # Forbid retries where repeated attempts are themselves security-relevant
  # (for example PIN entry against a hardware token).
  sign_with_token:
    action: piv_sign
    backend: yubikey
    retry: never
```

Omit `retry:` for the default (prompt, unlimited). `attempts` must be at least 1;
use `retry: never` to forbid retries entirely.

In non-interactive runs (`rite run --frontend headless`, dry runs) the retry
prompt resolves to abort, so a deterministic failure does not loop forever.
