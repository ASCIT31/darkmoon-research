# Agent hardening — failure modes found in the lab and how they were fixed

Running the agents against real labs (rather than unit tests) surfaced concrete failure modes. Each was fixed at the agent or toolbox level and re-validated. This is the test → gap → fix loop that produced the evidence corpus.

## Capability gaps (found because a lab required the technique)

| Lab that surfaced it | Gap | Fix |
|---|---|---|
| Azure Blob → Entra | Agent ignored **blob versioning** — deleted/versioned secrets were invisible | Anonymous versioned-blob enumeration (`?comp=list&include=versions`) then download by `versionId` |
| Azure Key Vault | No **secret-value extraction**; password-reuse pivot failed because the contractor UPN convention (`ext.first.last@`) was unknown; no **Storage Table** query | Key Vault secret-value extraction; UPN-derivation from secret name + verified domains + `ext.` convention; `az storage entity query` / Table REST |
| Reveal Hidden Files in GCS | GCP agent was credential-gated and could not act on a **public bucket** with no creds; no object-name fuzzing; no encrypted-archive crack | Anonymous public-bucket exception; ffuf object-name fuzzing; cewl → 7z2john → hashcat archive crack |
| SSRF with Gopher for GCP | Metadata phase assumed a header-settable request; a blind SSRF that strips the header was unhandled | **gopher:// smuggling** of a full raw HTTP request (double-encoded), `ya29` token used as a Bearer directly against the JSON API (not importable into gcloud) |
| OWASP IoTGoat | No firmware/IoT plane existed | New `firmware` agent: image extraction, credential/backdoor recovery, embedded-web command injection, live-device exploitation |

## Reliability gaps (found because a command hung or stalled a campaign)

A blocked command hangs the whole campaign: the toolbox never returns and no finding is pushed. These are now enforced in a shared execution-safety contract across every agent.

- **Raw `/dev/tcp` sockets** on stateful services (Redis, brokers) never receive EOF and block forever → always use the dedicated client, wrapped so the allow-list validates only the outer shell.
- **Interactive archive tools** (`7z x` without a password) wait on stdin forever → inspect with `7z l`, pass the password inline once cracked, and redirect `</dev/null` on every archive command.
- **The git pager** (`git show`/`log`/`diff` spawn `less` and wait for a keypress) caused a multi-hour hang → every git command runs with `--no-pager`.
- **Unbounded pickaxe** (`git log -p --all -S` on repos with large binaries) → bounded, binary-excluded, `timeout`-wrapped.
- **CPU brute-force stalls.** A mask/incremental crack of a slow hash (`$1$`/`$6$`/bcrypt/7-Zip) runs for hours on CPU → cracking is **GPU-gated**: with a GPU, mask/large-wordlist attacks are allowed; on CPU-only, only fast targeted wordlists run, and an uncracked hash is declared and skipped.
- **Over-long online SSH brute** against a slow embedded device → prefer offline cracking of a hash obtained via a shell already held; cap any online guessing at ≤11 attempts.

## Correctness regressions locked out

- **False-positive dispatch** — a specialist must require a *positive* Go/plane signal; the mere absence of other markers must never trigger it. Enforced by wiring checks in the anti-regression suite.
- **Report completeness** — the server regenerates the report from the database; a per-finding evidence section is mandatory, never grouped.
- **Severity discipline** — CORS origin-reflection with credentials is HIGH; intentionally-public secrets are not inflated; each rule is propagated to every agent.
