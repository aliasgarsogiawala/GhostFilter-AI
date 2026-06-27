# Future Enhancements

These items are intentionally outside the hackathon production scope. They should not be presented as shipped features.

## Production identity

- Replace the shared hackathon access code with email magic links, passkeys, or trusted OAuth login.
- Add account recovery, session revocation, and an admin-controlled judge/demo tenant.
- Move Convex authorization to first-class verified identity claims when the chosen auth integration is finalized.

## Model and evaluation

- Build a larger, versioned, multilingual benchmark with held-out test data.
- Measure false-positive rates by channel, language, and scam category.
- Add adversarial prompt-injection suites and indirect-injection documents.
- Use correction feedback to create reviewed training examples.
- Fine-tune or adapt an open model only after data consent, redaction, and evaluation processes exist.
- Add calibrated confidence and abstention for ambiguous cases.

## Ghosti

- Host the open model on production inference infrastructure instead of relying on a local Ollama process.
- Add retrieval over verified safety guidance and official support documentation.
- Let Ghosti explain a saved scan by ID without exposing another user’s data.
- Add streaming responses, conversation deletion, and explicit retention controls.
- Support Hindi and other high-priority regional languages.

## Threat intelligence

- Add attachment hashing and malware sandbox providers beyond the current optional checks.
- Cache domain reputation with expiry to reduce latency and API usage.
- Detect QR-code phishing in screenshots and PDFs.
- Add Unicode homograph and visual-domain similarity detection.
- Track campaign-level indicators without retaining unnecessary message content.

## Platform integrations

- Complete and validate Outlook against a production Microsoft tenant.
- Rebuild the browser extension around authenticated, least-privilege API access.
- Add Discord, Telegram, and enterprise webhook ingestion where platform policies permit it.
- Add agent-framework adapters for common tool and retrieval pipelines.

## Reliability and operations

- Replace in-memory rate limiting with Redis or another shared limiter.
- Add structured logs, tracing, uptime checks, and alerting.
- Add end-to-end tests for login, OAuth callbacks, scans, history, and deletion.
- Add encrypted-token key rotation and re-encryption tooling.
- Add backup, retention, export, and deletion policies.
- Introduce queues for large connected-source scans and provider backoff.

## Product experience

- Add a one-click redacted report for banks, platforms, and security teams.
- Add household or team safety workspaces with role-based access.
- Add guided incident response for compromised accounts.
- Add accessible localization and mobile-specific scan flows.
- Add trend views that distinguish real user data from demo fixtures.
