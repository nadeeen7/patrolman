# Nikto safety investigation (2026-10-14)

> **Status update (2026-10-15): Nikto is retired from PATROLMAN.** It is no longer
> part of the active product. The adapter (`backend/integrations/nikto.py`), its
> registry entry, its profile selection, its manifest entry, its executable-resolution
> branch, its environment-template entry and its API acceptance were all removed, so
> no code path can build or launch a Nikto command. This document is retained as the
> safety evidence behind that decision. Section 8's checklist is historical: it
> records what activation would have required, and it is not a roadmap. The
> retirement itself is pinned by `backend/tests/test_nikto_safety.py`; nothing in
> that suite downloads, installs or executes Nikto.

Outcome (2026-10-14, superseded by the retirement above): **Nikto stays
`DISABLED_FOR_SAFETY`.** No opt-in was added, no Nikto
executable was run, and no Windows security setting was read, changed or bypassed.
Two independent blockers make safe enablement impossible from here; both are recorded
below with the evidence behind them.

## 1. What was inspected

- `backend/integrations/nikto.py` — command builder, parser, `DISABLED` and
  `SAFETY_RESTRICTIONS` text, and the absence of any opt-in hook.
- `backend/services/executables.py` — Nikto is only ever resolved from an explicit
  `AVA_NIKTO_PATH`; PATH lookup alone returns `None`, and `.bat`/`.cmd`/`.ps1`/`.sh`
  shims are refused.
- `backend/services/process_runner.py` — fixed argv, `shell=False`, Windows job-object
  containment, hard timeout, shared output bound, whole-tree cleanup.
- `backend/services/target_validation.py`, `backend/services/scan_service.py` — scope
  checks and the disabled-tool guard that runs before command construction.
- `backend/services/tool_manager.py`, `backend/services/results.py`,
  `backend/services/reports.py` — status reporting, redaction and report pipelines.
- Existing tests in `test_execution.py`, `test_policy_classification.py` and
  `test_ten_tools.py` (the Nikto-specific test file was retired with the
  integration; `test_nikto_safety.py` now guards the retirement).
- The installed toolchain: Strawberry Perl 5.42.3 is present at
  `C:\Strawberry\perl\bin\perl.exe`; no Nikto file exists anywhere on this host and
  `AVA_NIKTO_PATH` is unset. The only Nikto-named file found is
  `~/.ava-tools/whatweb/addons/verify-nikto`, a WhatWeb add-on shell script that
  verifies Nikto *logs* — it is not Nikto and is unrelated to the detection.

## 2. Defender forensics (read-only)

`Get-MpThreatDetection` / `Get-MpThreat` / `Get-MpComputerStatus` were queried
read-only; no exclusion, quarantine action or preference was touched.

| Field | Value |
|---|---|
| Threat name | `HackTool:Perl/NiktoSanner.A` (ThreatID `2147794255`) |
| Detections | 2, ~3 minutes apart | 
| Initial detection time | 2026-10-11/12 (epoch 1791878634666 and 1791878829936) |
| Resources | `containerfile:_C:\Users\Nadeen\Downloads\nikto-main.zip`, `file:_...nikto-main.zip->nikto-main/program/nikto.pl`, `webfile:_...nikto-main.zip\|https://codeload.github.com/sullo/nikto/zip/refs/heads/main` |
| Action | `ActionSuccess: true` (remediated), `DidThreatExecute: false`, `IsActive: false`, execution status `0` |
| Defender state | `AMRunningMode: Normal`, real-time protection on, tamper protection on |

Interpretation, stated carefully:

- The detection does **not** prove malware. The flagged content was `nikto.pl` inside a
  ZIP that was downloaded and never executed (`DidThreatExecute: false`);
  `HackTool:Perl/*` is a generic heuristic family that security scanners genuinely
  trigger, and upstream Nikto is a legitimate open-source scanner.
- The detection does **not** prove safety either. There is nothing left to verify: the
  artifact was remediated, and it came from the rolling **`main` branch archive**, for
  which upstream publishes no checksum and which is not reproducible byte-for-byte.
  A `main`-branch ZIP also cannot be pinned to a reviewed commit the way a tagged
  release can.

## 3. Blocker 1 — origin and integrity cannot be established

- No Nikto distribution is present on this host; nothing can be hashed or reviewed.
- The previously detected copy is gone, and its provenance was a rolling branch ZIP
  with no published hash, so its integrity cannot be reconstructed.
- Establishing integrity would require obtaining a **tagged upstream release** with a
  published SHA256 and verifying it in a controlled staging directory. That is a
  security-administrator decision on an approved distribution, not something to be
  improvised here, and fetching another copy specifically to get past the existing
  detection is prohibited.
- The quarantine store itself (`C:\ProgramData\Microsoft\Windows Defender\Quarantine`)
  is not readable without elevation, and reading or restoring from it would be
  interacting with quarantined content — deliberately not attempted.

## 4. Blocker 2 — redirect and egress containment cannot be guaranteed

Nikto is a general-purpose HTTP client that follows redirects and can be pointed at
any host. PATROLMAN's application-level validation only guarantees the **initial**
target is loopback; it cannot prove that a redirect, a `Location:` header, or Nikto's
own request behaviour cannot reach a non-loopback destination. Proving that needs
host-level network containment (administrator-approved firewall/WFP rules, or a
network namespace equivalent) which this task forbids creating.

Per the integration requirements, "if redirect or network egress restrictions cannot
be verified, keep Nikto disabled" — so it stays disabled.

## 5. Decision and what was done instead

- Nikto remains `DISABLED_FOR_SAFETY`; the adapter exposes **no** opt-in hook, and no
  environment variable of any spelling enables it.
- Status reporting was kept honest: the inventory reports the detection, the missing
  verification, `operator_opt_in: null`, and `verification_type: mocked_fixtures`.
- The real Nikto adapter gained one conservative fix while under review: a severity the
  JSON item actually provides is now preserved (previously every Nikto finding was
  reported `unknown` even when the item carried a severity). The shared normalizer maps
  and validates it, and an absent value stays honestly `unknown`.
- 35 focused tests were added in `backend/tests/test_nikto_safety.py` covering: no
  opt-in hook, inert opt-in names, PATH-only discovery refusal, loopback-only targets,
  shell-metacharacter refusal, bounded argv, a child that ignores Nikto's own timeouts
  still being killed by the runner, non-success status mapping, no command construction
  and no subprocess while disabled, partial/unknown fields, malformed output, redaction
  through HTML/JSON reports, and honest severity normalization.

**These tests are mocks and fixtures. They are not evidence that a genuine Nikto
assessment works, and no genuine Nikto assessment was performed.**

## 6. Safe next steps (all outside this task's authority)

1. Security administrator selects an approved, **tagged** Nikto release and records its
   published SHA256; verify the hash in a controlled staging directory without granting
   exclusions or restoring quarantined content.
2. Confirm with the security team that the Defender verdict for that approved artifact is
   either cleared or explicitly accepted as a vendor false positive, and document the
   decision.
3. Approve and implement host-level egress containment for loopback-only scanning, then
   demonstrate it with a redirect trap (a local server redirecting to a non-loopback
   sink) proving no request leaves the loopback boundary.
4. Only then add a **separate** Nikto opt-in (independent of every other tool's
   opt-in) and run a genuine end-to-end assessment against a fresh
   isolated local fixture, checking findings in results, history and both report formats.

## 7. Follow-up research (same day): upstream artefact verification and egress paths

Read: the official Nikto README and `program/nikto.conf.default`, the repo's
`documentation/nikto.1` man page and `program/nikto.pl`, Microsoft's threat page for
the detection, and Microsoft's guidance on false positives/negatives.

**Upstream publishes nothing to verify against.** No SHA-256/checksum file, no GPG
signature, no signing mechanism, and no documented download-verification procedure
exists for Nikto — not for the tagged 2.6.0 source archives, and not for the moving
`nikto-main.zip`. The README's installation instructions are `git clone` plus running
`program/nikto.pl` (or Docker), with no integrity step. Microsoft publishes the
detection as `HackTool:Perl/NiktoSanner!A`, and its general false-positive guidance
says to submit a suspected false positive for analysis and warns that exclusions
reduce protection — it does not declare this detection benign.

**How redirect-following could escape the authorized target.** Documented findings:

- `-followredirects` is **not** a default; the default configuration sets no
  `FOLLOW_REDIRECTS`. PATROLMAN never passes it, so the built argv does not enable
  redirect following.
- Upstream's option text says "follow 3xx redirects to new location" and does **not**
  document whether that is confined to the authorized host. Any future version could
  also change that behaviour, so "we do not pass the flag" is a current-version
  argument, not a containment proof.
- `-nolookup` is **not** a scope control: upstream documents it as "do not perform
  name lookups on IP addresses", i.e. it does not pin a hostname to an approved IP and
  cannot prevent DNS answers from changing mid-scan.
- Other documented egress paths exist beyond redirects: `-mutate 5` brute-forces
  sibling subdomain names (not used by PATROLMAN's argv), `-check6` deliberately
  contacts `ipv6.google.com` or a configured `CHECK6HOST`, and the main script performs
  an update/version check against an external API unless suppressed. PATROLMAN now
  passes `-nocheck` to suppress that update check — necessary, but nowhere near
  sufficient, and no flag can be proven to contain a general HTTP client.
- Upstream documents **no** network-isolation, egress-restriction or safe-lab guarantee.

**Conclusion unchanged, now with exact blockers.** Nikto stays `DISABLED_FOR_SAFETY`
because (1) there is no published checksum or signature to establish artefact
integrity, and the previously flagged copy is gone and came from a moving branch
archive; and (2) containment cannot be demonstrated without host-level network
isolation, which this task must not create. Neither Windows Firewall nor any other
system-wide setting was read for modification, changed, or disabled, and no antivirus
exclusion was created.

## 8. Activation checklist — the exact evidence that was required

*(Superseded by the 2026-10-15 retirement. Retained as the record of what
activation would have needed; no item below is being pursued.)*

Nikto was deliberately listed in `backend/approved_binaries.json` with a `null`
digest: it could not be approved while any item below was unmet. Activation needed ALL of:

1. **An approved distribution with a recorded digest.** Upstream publishes no
   checksum or signature for any Nikto archive (verified: README, default config,
   man page, tagged 2.6.0 file listing), so the digest must be established and
   recorded by the security function from a specific, reviewed artifact — then pinned
   in the manifest like every other tool. The previously flagged artifact cannot be
   used: it was remediated, and it came from the un-tagged moving `main`-branch ZIP.
2. **A documented disposition of the Defender detection** `HackTool:Perl/NiktoSanner!A`
   for that exact artifact (cleared, or accepted as a vendor false positive in
   writing). No exclusion, no quarantine restore, no Defender change will be made by
   this project to obtain it.
3. **Host-level network containment evidence.** Application-level validation only
   fixes the initial target. Required is a demonstrated control (approved firewall or
   equivalent egress rule) plus a redirect-trap test proving a redirect from the
   authorized loopback service cannot reach a non-loopback destination. Our argv
   already omits `-followredirects` and passes `-nocheck`, but upstream documents
   neither cross-host redirect behaviour nor any egress guarantee, and `-nolookup`
   is not a scope control — so flags alone are not evidence.
4. **A separate opt-in.** Nikto's opt-in must be independent of every other tool's
   opt-in, and must not exist until 1–3 are satisfied.
5. **A genuine end-to-end run** against a fresh isolated local fixture, with findings
   confirmed in results, history and both report formats.

Until every item is satisfied, Nikto remains `DISABLED_FOR_SAFETY` and no Nikto
executable is invoked, copied, restored or downloaded.
