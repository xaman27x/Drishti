# ADR-0001: Use OCSF as the normalized event contract

- Status: Accepted
- Date: 2026-09-26
- Decision owners: Drishti architecture team

## Context

Drishti must convert heterogeneous perimeter-device evidence into a consistent
security-event representation without creating another proprietary event
taxonomy. It must also run in an air-gapped environment and reproduce historical
normalization after upstream schemas evolve.

Depending on the live OCSF schema server would break air-gap operation. Tracking
the upstream development branch would make replays non-deterministic. Modifying a
private fork of OCSF core would create interoperability and upgrade problems.

## Decision

1. OCSF is Drishti's canonical normalized-event contract.
2. The official OCSF `1.9.0` schema payload is vendored without modification at commit
   `856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba`.
3. A deterministic tree hash detects changes to the vendored schema payload. Upstream
   `.github/**` automation and `.vscode/**` editor settings are excluded from the
   contract hash and never executed.
4. Drishti-specific provenance is defined in a separate extension.
5. `ocsf-lib==0.10.4` compiles OCSF core plus only the Drishti extension into a
   canonical JSON artifact during development; optional Linux, macOS, and Windows
   extensions are deliberately disabled to prevent extension-order collisions.
   The compressed artifact is committed and loaded locally at runtime.
6. Every normalized event is validated against the exact bundle digest recorded
   in its conservation certificate.
7. OCSF upgrades require a new ADR, compatibility report, regenerated fixtures,
   parser qualification, and controlled replay impact analysis.

## Security boundary

The schema bundle defines allowed structure and semantics; it never executes
parser code. The AI onboarding plane may propose mappings but cannot modify the
bundle, approve a parser, or publish normalized events.

The private Drishti extension UID is not an official OCSF allocation. Before a
public interoperable release, the extension must be registered upstream or
assigned a formally governed organizational namespace.

## Consequences

- Deployments do not need internet access.
- Every result is tied to exact OCSF, extension, and parser identities.
- Schema upgrades are deliberate rather than silently inherited.
- The repository grows by approximately 2.5 MB because the authoritative schema
  source and license are carried with the product.
- The first validator intentionally rejects unknown fields. Vendor-specific data
  must be represented by an approved extension or preserved in raw evidence.
