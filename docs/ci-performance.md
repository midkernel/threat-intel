# CI performance and contributor checks

## Existing hosted baseline

The read-only baseline collected on 2026-11-01 at 14:28:43–14:28:49 UTC pinned
this repository to `b63a023000fc0e056ae08e9336487a12a7d17fa1`. Of the latest 50 runs,
only three were ordinary PR/main-push CI; the other 47 were scheduled collection
and were excluded. All three selected CI attempts succeeded. Their workflow text
matched the pinned ordinary CI workflow, though source inputs can differ. No new
hosted run was started for this change.

| Run (attempt 1) | Event | Created UTC | Workflow wall | Job execution | Scheduling proxy | Check steps |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| [41191723243](https://github.com/midkernel/threat-intel/actions/runs/41191723243) | PR | 2026-10-31 10:11:22 | 15s | 7s | 8s | 0s |
| [41191998584](https://github.com/midkernel/threat-intel/actions/runs/41191998584) | PR | 2026-10-31 10:15:21 | 11s | 8s | 3s | 1s |
| [41292024306](https://github.com/midkernel/threat-intel/actions/runs/41292024306) | main push | 2026-11-01 09:11:28 | 9s | 6s | 2s | 0s |

The unchanged `validate-sources` job performs checkout, sources validation,
offline index tests, offline collector tests, offline backfill tests and validation
of committed backfill, using stdlib Python without an install step. Setup totals
were 2/2/2s; teardown 1/0/1s; unattributed execution residuals 4/5/3s, respectively.
Second-resolution timestamps explain the zero-second check deltas; zero does not
mean checks were skipped. Wall is workflow creation to final job completion;
scheduling is job-created-to-start, not a measured push-to-feedback delay.
Historical evidence is from the supplied baseline; these links were not freshly
fetched during implementation.

## Bounded change

Only ordinary `.github/workflows/ci.yml` gains concurrency: older runs for the
same PR can be cancelled; non-PR groups include run ID and attempt and never
cancel. Separate main runs therefore neither cancel nor share a pending group.
Every existing job/status, trigger, permission and validation/test step remains.
No selector, skip, sharding, cache, dependency or linter/typechecker was added.
The already short baseline does not justify a more complex acceleration scheme.
This targets redundant PR work, not measured single-run acceleration.

The collection and backfill workflows, schedules, secrets, readiness, records and
committed data remain unchanged. Explicit developer setup checks Python/Git
prerequisites and installs the accepted per-worktree gate without downloading
anything. Its direct adapter validates the local source registry and committed
backfill only; it does not collect, generate, publish or probe URLs/MCP. This is
schema/catalog validation, not Python formatting, lint or typing. CI keeps its
full existing coverage. See [pre-push coverage and limits](prepush.md).

## Local validation on 2026-11-01

Linux, Git 2.43.0 and Python 3.12.3 were used. Real contributor setup completed in
0.1033s and installed the dispatcher and enrollment marker. No dependency install
was needed. Three interleaved local samples compared the unchanged validator
pair on pinned source with the new direct quick adapter:

| Local command | Samples (seconds) |
| --- | --- |
| Pinned source, both validators | 0.2721, 0.2552, 0.2294 |
| Working source, quick adapter | 0.2690, 0.2822, 0.3045 |

These are local smoke timings with warm-cache/order effects, not hosted speedup
estimates. A successful bare-Git push including the installed hook took 0.4084s.
Setup, validators and push times measure different operations.

The four shared dispatcher/install/check/test files match the independently
accepted implementation byte for byte. Its 29 synthetic tests passed once and
are reused for both matching repository copies. Actual disposable bare-Git
pushes additionally proved that an invalid source-registry URL and a wrong
backfill manifest schema each block ref updates, while their corrected tips pass.
Dirty/staged/untracked state, unsupported multi-ref, tag and non-HEAD pushes, and
missing Python blocked without changing bare remote refs. The owned, deliberately
uncommitted checkout was enrolled and its real installed hook rejected its dirty
state. Validators have no third-party dependencies to omit or silently skip.

Both validators passed independently with a Python diagnostic network sentinel;
the 30 existing offline index tests passed with no skips in 0.1930s including
interpreter/wrapper startup. No sentinel network attempt was observed in these
Python runs. This is a diagnostic control, not an OS sandbox. Collector and
backfill-generation test entrypoints were not executed locally in this bounded
task; all their existing CI steps remain unchanged. No collection, generation,
publishing, registry availability check or production/MCP probe was performed.

Individual shell syntax checks, Python AST parsing, whitespace checks and
actionlint 1.7.7 passed. Optional actionlint shellcheck/pyflakes integrations were
explicitly disabled. Removing the new concurrency block reproduces the original
workflow byte for byte. HEAD, index and Git config are preserved, and no lockfile
was introduced. All project edits remain unstaged and uncommitted for review.

## Hosted after results: pending

No hosted after timing, cancellation behavior, branch-protection result or speedup
is claimed. After publication, sample ordinary CI using the same latest-50 and
three-completed-run method, ensuring PR/main coverage and continuing to exclude
operational collection. Retain SHAs, attempts, outcomes, job/step timestamps and
runner context. Compare PR and main separately, with failures/cancellations/skips
kept separate. Confirm same-PR superseded cancellation, independent PR/main runs,
and every existing failure status. Report avoided redundant work separately from
successful-run wall time; cancelled or missing checks are not passing checks.
