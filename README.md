# Codex Gate

Codex Gate is a local control plane that separates ChatGPT-style planning from Codex execution. It keeps model choice, approval policy, workspace bounds, and run state under one UI.

## What it does

- Connects to `codex app-server --stdio`
- Loads the installed Codex version and generated JSON schema
- Starts runs in `thread/start` and `turn/start`
- Keeps Workspace Write locked in this release
- Uses ephemeral threads for Read Only runs and attempts `thread/unsubscribe` after completion
- Streams approval requests to the UI over SSE
- Stores tasks and artifacts in SQLite under the data root
- Reads account auth mode/plan, account-wide rate-limit snapshots, daily usage summaries, and the app-server model catalog
- Stores the Web GPT decision and side-effect-free router result as an immutable, expiring Route Plan
- Starts Read Only execution only from the final model and effort sealed into a valid Route Plan

## Run it

```powershell
cd C:\Users\82109\Documents\Codex\2026-07-26\dl\outputs\CodexGate
python -m pip install -r requirements.txt
.\run.ps1
```

For development reloads:

```powershell
.\run_dev.ps1
```

Open `http://127.0.0.1:8787`.

## Account and router preview

After connecting, Codex Gate stores only the following local account data:

- Auth mode and plan type from `account/read`; any email is masked before storage and display.
- The account-wide `account/rateLimits/read` snapshot, including usage percentages and reset times. It is **not** treated as a per-model remaining balance.
- Daily `{startDate, tokens}` rows from `account/usage/read`; aggregate usage details are not stored.
- Model IDs, display names, server-returned reasoning-effort order, and service tiers from `model/list`.

`account/rateLimits/updated` is sparse-merged into the last rate-limit snapshot. Failed or incomplete account queries are stored as `UNKNOWN`, never as zero. Account state uses the maximum `usedPercent` across every primary/secondary window, including `rateLimitsByLimitId`; `spendControlReached` or `rateLimitReachedType` immediately means `BLOCKED`. The response records the window and percentage used for the calculation. Default states are `NORMAL` below 70%, `CONSERVE` at 70%, `CRITICAL` at 90%, and `BLOCKED` at 100%; local settings can change these thresholds. Manual model states (`AVAILABLE`, `LIMITED`, `DEPLETED`, `UNKNOWN`, `DISABLED`) remain separate from the account-wide limit.

The router preview accepts a Web GPT recommendation as a ceiling and only chooses values advertised by `model/list`. Unknown task classes hold for reclassification. T1 is limited to two files, T2 to five, and T3 to ten; a larger task holds and requests the next class. Its minimum efforts are T0 Medium, T1/T2 High, T3 High (Very High at four files), T4 Very High, and T5 model-specific: Sol requires Max while 5.5 requires its highest advertised non-Ultra effort. `xhigh`, `x-high`, `very-high`, `very high`, and `매우 높음` are one semantic stage; the final value is always the target model's server-returned literal.

Only low-risk Read Only work can downgrade to its class's lowest safe model. Low-risk Write work needs tests and can move at most two model grades; medium/high-risk work never auto-downgrades. `DISABLED`, `DEPLETED`, and `UNKNOWN` models are never selected automatically, while `LIMITED` follows available candidates with a warning. `BLOCKED` holds all previews; `CRITICAL` holds T3–T5 and prohibits Ultra; `CONSERVE` prohibits Ultra and permits only low-risk downgrade previews. Unknown account state emits a warning without usage-driven routing. Ultra is previewed only for a Read Only parallel audit with at least three independent axes and explicit approval. No preview changes `thread/start` or `turn/start`; Workspace Write and Ultra execution remain locked.

## Route Plans

Paste the Web GPT decision JSON and create a Route Plan before running Codex. `Decision` includes `risk`, `parallel_audit`, and `independent_axes` in addition to its task class, recommendation, file scope, validation commands, and stop conditions. Codex Gate canonicalizes the validated decision JSON and records its SHA-256.

`allowed_files` is a closed project-relative scope. Every entry must name an exact file; absolute paths, glob patterns, directories, root traversal, symlink/junction escapes, and duplicates outside the canonical scope cause a `HOLD`. `planned_file_count` is the number of unique validated entries, never the indexer's project file count. Test evidence is not inferred from task wording: the plan records `validation_commands_present` and `local_test_target_exists` separately, and only considers both together as test evidence.

Each immutable SQLite Route Plan records its ID, original task text and hash, resolved root, project ID, permission, decision hash, account snapshot time/state, model catalog hash, final model/effort, candidate ladder, HOLD reasons, validation evidence, and an exact budget. The default TTL is 10 minutes. Budget is fixed by class: T0/T1 `tiny`, T2/T3 `standard`, T4 `complex`, and T5 `critical`.

Execution accepts exactly one field: `route_plan_id`. Root, task, project ID, permission, model, effort, and budget are read only from the sealed plan; extra `model`, `effort`, or `budget_level` fields receive HTTP 422. The Gate rejects the same direct-input shape internally, so there is no legacy execution adapter.

Only `PREVIEW`, Read Only, non-Ultra plans can run. A SQLite transaction atomically claims a plan, then records `claimed → started → failed|completed`; a failed start remains consumed and requires a new plan. A partial start attempts interruption or unsubscribe. Execution rejects a missing, expired, modified, used, or HOLD plan, and rechecks the account and selected model: a worse account state or a final model now marked `DEPLETED`, `UNKNOWN`, or `DISABLED` invalidates the plan. `thread/start` and `turn/start` receive only the plan's final route. Results retain `route_plan_id`, `decision_hash`, requested/actual model, and reroute reason. `model/rerouted` is recorded and `thread/compacted` immediately interrupts the turn; the 80% token warning is emitted only once per run.

To print a redacted live account/model summary without writing credentials or email addresses:

```powershell
python scripts\probe_account.py
```

## Data root

The app stores its local state under `CODEX_GATE_HOME`.

- Default: `C:\Users\<you>\CodexGate`
- Override with: `CODEX_GATE_HOME`

## Forbidden roots

Workspace access is blocked for forbidden roots before preflight and run execution.

- Default forbidden root: `E:\.codex`
- A workspace is rejected if it is the forbidden root, inside it, or a parent of it (for example `E:\`)
- Override or add more with: `CODEX_GATE_FORBIDDEN_ROOTS`

Task text, decision payloads, and approval request command/path data that reference a forbidden root are rejected and recorded with a clear stop reason.

## Security notes

- Only `127.0.0.1` and `localhost` are accepted as `Host`
- If `Origin` is present, it must match the same local origin
- `project_id` must be a safe slug or UUID
- Artifact names are limited to an internal allowlist
- Workspace Write stays locked until the write-validation step is explicitly enabled in a later release
