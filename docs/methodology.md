# Methodology

## Architecture

Darkmoon is an orchestrator plus specialist sub-agents. The **orchestrator** (`pentest`) is a signal-detection finite-state machine: it performs recon, fingerprints the technology stack, and dispatches the matching specialist(s). Each **sub-agent** is a self-contained playbook injected verbatim as a system prompt; it runs autonomously against the MCP-backed toolbox and pushes findings as it goes. A live dashboard streams every finding, infrastructure node and agent event.

Sub-agents are byte-identical across the Community / Pro / Front-API editions except the environment-specific `ad`, `kubernetes` and `pentest` files, so a result reproduced on one edition holds on the others.

## Dispatch model

Two dispatch regimes:

1. **Auto-dispatch (web/CMS agents).** Fire on a stack signal (a framework header, a CMS fingerprint, a GraphQL endpoint). Cheap to run, low false-positive cost.
2. **Artifact-gated dispatch (cloud, identity, CI/CD, IaC, data, secrets, firmware).** Fire **only** on a concrete *positive artifact* — a leaked credential, an exposed API/port, a metadata response, a firmware image, or operator-supplied scope. Never on inference, and never on the mere *absence* of other signals.

The artifact gate is the central correctness mechanism. Attacking a plane because a name merely *looked* cloudy is the dominant failure mode of automated cloud testing; requiring a positive artifact eliminates it. This mirrors the manual-only discipline serious testers already apply to Active Directory and Kubernetes.

## The exploitation loop

For each dispatched agent:

1. **Preflight.** Verify the artifact and the reachable scope; abort with a root-cause if the gate is not actually satisfied.
2. **Enumerate.** Map the blast radius before acting.
3. **Exploit with proof.** A state-changing action is taken only as the minimal proof of a finding. Every finding records the exact command and its raw response.
4. **Cascade.** Material recovered on one plane (a cloud key, a git token, a DB DSN, a kubeconfig, a firmware credential) is recorded as a fact so the orchestrator can dispatch the next specialist. Cascade depth is capped to prevent runaway recursion.
5. **Re-fingerprint.** After a sub-agent returns, its results re-enter the signal matrix, so a newly discovered surface can trigger a further dispatch.

## Evidence and status qualification

Reports are generated **server-side from the pushed findings**, not from free-form model text, so report quality is a function of per-finding evidence completeness (raw request/response, exploitation commands, explanation, remediation, CVSS 3.1, MITRE ATT&CK).

Each finding's status is assigned adversarially by *demonstrated* impact, never by observation:

- **EXPLOITED** — impact executed end-to-end (data extracted, action performed, access gained).
- **CONFIRMED** — impact demonstrated with an exact payload + raw response + extracted data or execution trace.
- **UNCONFIRMED** — a real lead, observed but not yet proven; capped at low severity.

Before writing CONFIRMED/EXPLOITED the agent must try to break its own claim. This keeps finding *counts* honest — better qualification, not fewer findings.

## Reproducibility

Cloud engagements use public training labs with provider-issued lab credentials. Firmware engagements use the public OWASP IoTGoat image under emulation. Local-infrastructure engagements use disposable Docker services. VPN-gated labs are reached by routing the containerized toolbox through the lab VPN with split-tunnel routes, so only the in-scope targets traverse the tunnel while the dashboard and control plane stay local.
