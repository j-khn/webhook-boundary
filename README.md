# Webhook Boundary

> **Status:** Early-stage reference implementation; APIs may change.

A small, dependency-free verifier for webhook signatures over the exact request bytes.

Signature bugs often come from normalizing JSON before verification, accepting ambiguous timestamp headers, or forgetting that a valid signature can be replayed. Webhook Boundary keeps the cryptographic boundary explicit: provide the raw body, original signature header values, active secrets, and a clock.

## ✨ Example

~~~python
from webhook_boundary import verify_signature

verified = verify_signature(
    raw_body=request_body,                 # exact bytes received by the server
    signature_headers=signature_headers,   # preserve repeated header fields
    secrets=[current_secret, old_secret],  # allow a short rotation window
    now=1_735_689_600,
    tolerance_seconds=300,
)
print(verified.timestamp)
~~~

The example header format is t=<unix-seconds>,v1=<hex-hmac>. A signing helper is included for local examples; production secrets should come from a secret manager.

## What it checks

- HMAC-SHA256 over timestamp, separator, and unmodified body bytes.
- Constant-time comparison against every candidate signature and active secret.
- A bounded timestamp window using an injectable clock.
- Duplicate timestamp rejection and malformed signature rejection.
- Multiple v1 signatures for safe secret rotation.

## Install

~~~sh
python -m pip install .
~~~

The package includes a `py.typed` marker so type checkers can use its public annotations.

## Security boundary

Provider SDKs such as [Svix](https://github.com/svix/svix-webhooks) and [Tern](https://github.com/Hookflo/tern) already cover common production formats. This small package is a provider-neutral reference for the documented t/v1 format and verifies authenticity and freshness. It does not deduplicate provider event IDs or make webhook handling exactly-once. Persist the provider event ID under a unique constraint before applying side effects. Each provider defines its own signing format; adapt the header parser rather than assuming this example format is universal.

## License

MIT.
