# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/Actenon/actenon-permit/security/advisories/new) or email `security@actenon.dev` (`ross.buckley1990@gmail.com` with subject prefix `[ACTENON SECURITY]`) with:

1. A description of the vulnerability and its impact.
2. Minimal reproduction steps.
3. The affected `actenon-permit` and `@actenon/sdk` version.
4. Whether the issue affects grant signing, delegation attenuation, atomic budget/effect reservation, credential brokering, or provider adapters.

You will receive an acknowledgement within 72 hours.

## Threat Model & Enforced Boundaries

| Boundary | Enforcement Mechanism |
|---|---|
| **Grant Integrity & Revocation** | HMAC-SHA256 signed grants verified by `PDP`; revoked grants fail closed with `GRANT_REVOKED` / `AUTHORITY_REVOKED` before proof minting or credential resolution. |
| **Exact Effect Binding** | Finite grants with `approved_effect_ids` bind policy, Ed25519 `PCCB` proof minting, Kernel verification, and adapter execution to the exact `ACTENON-JCS-STRICT-1` canonical request digest (`effect_id`). |
| **Delegation Attenuation & Ancestor Spend** | Sub-agent delegation (`delegate()`) enforces strict capability, rate, expiry, and spend attenuation. Delegated spend is atomically charged against the sub-grant and every authenticated ancestor grant. |
| **Server-Side Credential Brokering** | Raw provider credentials are resolved only inside the broker after `PDP` authorization and `PCCB` proof verification; raw secret values are redacted from all receipts, refusals, and error messages. |
| **Dynamic Adapter SSRF & Origin Pinning** | `OpenAPIDynamicAdapter` pins credentials to the configured origin, refuses cross-origin HTTP redirects before forwarding `Authorization` headers, blocks loopback/private/link-local (`169.254.169.254`) SSRF targets, and enforces post-action read-only witness `reconcile()`. |

## Supported Versions

| Version | Supported |
|---|---|
| `2.0.x` (`2.0.0rc1`) | Yes |
| `< 2.0` | No |
