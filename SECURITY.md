# Security Policy

## Reporting a Vulnerability

Please do NOT open public GitHub issues for security vulnerabilities.

To report a security issue, follow the Red Hat security reporting process:

- Email: [secalert@redhat.com](mailto:secalert@redhat.com)
- Details: <https://access.redhat.com/security/team/contact>

Alternatively, use GitHub's private vulnerability reporting on this
repository ("Report a vulnerability" under the Security tab) if it is
enabled for your account.

Please include:

- The affected function or module and the commit
- A description of the issue and its impact (for example, a layer that verifies when it shouldn't)
- Reproduction steps or a proof of concept where possible

## Scope

This policy covers `traust_ledger.integrity`: canonical event bytes, the Merkle tree and its proofs, signing and verification. Storage, authentication and who may write live in traust-core and fall under its policy.

## Supported Versions

There are no releases: consumers pin a commit. Fixes land on `development`; consumers take them by moving their pin.
