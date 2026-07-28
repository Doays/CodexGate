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
- Builds a bounded, read-only Evidence Capsule from the Route Plan's explicit evidence scope without starting Codex

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

`evidence_files` and `evidence_ranges` are a separate, read-only scope included in the canonical Decision hash. `evidence_files` contains exact project-relative files. Each `evidence_ranges` entry is `{ "path": "relative/file.py", "start_line": 1, "end_line": 40 }`. Globs, directories, absolute paths, root traversal, symlinks, junctions, `E:\` paths, and `E:\.codex` paths cause a Route Plan `HOLD`. At Route Plan creation, Codex Gate stores only the SHA-256 and byte size of each explicitly named evidence source; it never enumerates the project tree.

## Evidence Capsules

Create an Evidence Capsule only from an unexpired, unclaimed `PREVIEW`, Read Only Route Plan. `HOLD`, expired, claimed, Workspace Write, and Ultra execution paths cannot create one. The app writes the capsule under `DATA_ROOT/capsules/<plan_id>/<capsule_id>` and does not call `thread/start`, `turn/start`, or any app-server RPC. The capsule has exactly the approved task and plan metadata plus either whole text files or line-numbered snippets; API/UI output contains status, file count, byte size, evidence fingerprint, and reasons only—never source bodies.

An evidence path may be a whole file or a line-range source, never both. Whole-file sources are `stat`-checked before reading and must be at most 128 KB. Range sources are streamed as bounded binary lines: the full SHA-256 is calculated while only selected lines remain in memory. Each range is limited to 250 lines, each source to 1,000 captured lines, and each single line to 64 KB. The entire capsule, including `TASK.md`, `ROUTE_PLAN.json`, and `EVIDENCE_MANIFEST.json`, is limited to 15 files and 1 MB. Limits never truncate: the result is `HOLD`. Only ASCII, UTF-8, and UTF-8-SIG sources are accepted. Binary or unsupported-encoding sources are not copied; their sealed metadata remains recorded and the result is `HOLD`.

`EVIDENCE_MANIFEST.json` records each relative source path, capture mode, source SHA-256, sizes, requested line ranges, and capsule path. Its canonical payload plus generated-file hashes forms the Route-Plan-instance `capsule_hash`; it deliberately includes the plan binding. `evidence_fingerprint` is separate and excludes `plan_id`, covering task hash, decision hash, normalized evidence scope, and source SHA-256, so equivalent evidence from separate plans has the same fingerprint. Before returning an existing `READY` capsule, Codex Gate recalculates the manifest canonical hash and every generated-file SHA-256, rejects missing/extra files and links/junctions, and compares the recomputed instance hash with SQLite. A changed, missing, or tampered capsule becomes `INVALID` and requires a new Route Plan; it is never automatically restored to `READY`. Generated capsule files are marked read-only and the local store permits only one active capsule record for a Route Plan.

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

## Read isolation gate

Before any live Read Only run, use **Test Read Only isolation**. The probe creates two random canaries only under `DATA_ROOT/isolation-probes`: one in a capsule directory and one sibling outside it. A throwaway app-server connection performs only two standalone `command/exec` requests with the generated-schema `readOnly` sandbox policy, capsule `cwd`, a 10-second `timeoutMs`, and a matching asyncio timeout. The request deliberately omits `outputBytesCap` and `disableOutputCap` on Windows and uses the server default cap instead. It never calls `thread/start` or `turn/start`, so it consumes no model turn or model tokens.

The fixed command is `sys.executable -I -S -c ...` and prints only one ASCII marker: `READ_OK`, `READ_DENIED`, or `READ_ERROR`. Output is normalized with `splitlines()`, and any response larger than 1 KB is treated as `ERROR`. An outside `READ_OK` means `UNSAFE_FULL_DISK_READ`. Only an inside `READ_OK` with an outside explicit `READ_DENIED` becomes `SAFE_CANDIDATE`; ordinary failures, timeouts, blank output, and `READ_ERROR` are all `ERROR`, never safe. This release does not mint new `SAFE_CAPSULE_ONLY` results, and `SAFE_CANDIDATE` does not unlock live execution. Stored `ERROR`, `UNSAFE_FULL_DISK_READ`, and `UNKNOWN` results block immediately. The database retains only status, timestamps, Codex version, generated-schema SHA-256, canary SHA-256 values, and sanitized result codes—not canary content, paths, commands, or raw stdout/stderr. Results expire after 24 hours and safe-style results become `UNKNOWN` when the installed version or schema changes. The UI shows the isolation state and whether the outside read succeeded or was explicitly denied, but the live execution button stays locked in this release.

- Only `127.0.0.1` and `localhost` are accepted as `Host`
- If `Origin` is present, it must match the same local origin
- `project_id` must be a safe slug or UUID
- Artifact names are limited to an internal allowlist
- Workspace Write stays locked until the write-validation step is explicitly enabled in a later release

## Manual Web GPT Bridge

The Web GPT Bridge is deliberately semi-manual: Codex Gate never controls a ChatGPT page, sends a packet to the web, monitors the clipboard, or collects a web response automatically. One visible action is enabled for each Bridge task: copy an architecture packet, import an architecture response, prepare/copy a review packet, import a review response, or restart a terminal state. Copy uses `navigator.clipboard.writeText` after a click and opens an optional task-specific ChatGPT URL only after that copy succeeds. Clipboard reads occur only after the user presses the import action; a failed `readText` exposes a manual paste field.

Packets are one marker block: `BEGIN`, then one JSON object body, then `END`. Request envelopes and response envelopes are intentionally different. Requests include `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `CREATED_AT`, `EXPIRES_AT`, `SCHEMA_VERSION`, `BODY`, and the locally calculated `REQUEST_SHA256`. Responses require only `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `SCHEMA_VERSION`, and `BODY`. The maximum packet size is 60KB. A nonce is one-use; task, phase, type, nonce, and required fields must all match. Unknown response fields, missing markers, truncated packets, and multiple marker blocks are rejected.

Outgoing `ARCHITECT_REQUEST` packets carry only the local task, constraints, and questions—never a project root, repository body, game source, full logs, or secrets. Secret-like values and absolute user paths put the Bridge task in `HOLD` before copying. `ARCHITECT_RESPONSE` is either `execute` (which invokes the existing local Route Plan creator) or `need_more_evidence` (which exposes only the requested evidence names and creates a fresh architecture nonce). A HOLD Route Plan never enables Codex execution.

`REVIEW_REQUEST` can be made only after a Route Plan is ready and the user provides actual result and local-validation summaries. `REVIEW_RESPONSE` accepts only `SUCCESS`, `HOLD`, `RETRY`, `REDESIGN`, or `ROLLBACK`. `RETRY` starts a fresh architecture cycle with a new nonce and no Route Plan or Codex-thread reuse; `REDESIGN` and `ROLLBACK` remain explicit terminal states until restarted. The Bridge database retains copy/receive timestamps and response hashes, not clipboard text or Web GPT response text. Packet preview/import does not call app-server RPC.

### Protocol v2

Bridge requests use schema version `2.0`. Codex Gate fixes `CREATED_AT` and `EXPIRES_AT` (30 minutes) when the request is created, then includes a locally calculated `REQUEST_SHA256`. Re-copying or re-opening the same waiting request returns the identical packet and hash. Web GPT responses intentionally require only `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `SCHEMA_VERSION`, and `BODY`; Codex Gate canonicalizes the received response itself and stores only its resulting hash.

Every v2 request embeds an exact `RESPONSE_CONTRACT`, including `execute` and `need_more_evidence` architecture bodies plus examples for every review verdict. The parser extracts exactly one marker block from pasted text, so a single Markdown code fence and surrounding explanation are accepted. Missing, truncated, or duplicate marker blocks remain rejected, as do unknown response fields and mismatched task/phase/nonce values.

The response envelope, task, phase, nonce, expiry, and validated BODY are checked before the nonce is claimed. Unsafe BODY content such as secret-looking values or absolute user paths is rejected before claim, so the same nonce can still be corrected and pasted again. Once a response is being processed, the task enters `PROCESSING_RESPONSE` and the import action is disabled. Replaying the same response hash is idempotent; a bridge idempotency key prevents duplicate Route Plans. If a response arrives after expiry, the task and nonce are atomically moved to `HOLD` with `expired_response`. If plan creation fails, the nonce is marked failed and the task moves to `HOLD`. `RETRY` keeps its sanitized review verdict/notes for the next architecture packet while clearing stale requested evidence, and `REDESIGN` preserves its review feedback for the next restart.

`need_more_evidence` now stores up to 20 structured requests with exactly `type`, `label`, `reason`, `required`, and `target_hint`. Supported types are `file_metadata`, `fast_fingerprint`, `text_range`, `log_excerpt`, and `json_structure`; `target_hint` is descriptive only. The user must map each request to one exact project-relative source file. Absolute paths, globs, directories, traversal, symlink/junction escapes, `E:\`, `E:\.codex`, and sensitive names such as `.env`, keys, certificates, credentials, and service accounts are rejected. `file_metadata` reads only stat data. `fast_fingerprint` reads at most the first and last 1MB, even for a 20GB file. Text ranges are limited to 250 lines (1,000 per file); log excerpts to 200 lines; JSON output contains structural keys, types, and array lengths but never scalar values. Binary sources are limited to metadata/fingerprint.

Evidence requests and redacted result metadata are stored locally with `REQUESTED → MAPPED → COLLECTING → READY` (or `FAILED`/`REJECTED`) states. A source result is capped at 32KB and all web evidence at 50KB. Secret-like text, authorization material, database URLs, and absolute user paths cause failure rather than masking. Every emitted source path is `PROJECT_ROOT/<relative>`. When every required request is `READY`, the Bridge creates a fresh architecture nonce and includes the collected results, their deterministic hashes, and collector version in the next `ARCHITECT_REQUEST`; those values are therefore covered by `REQUEST_SHA256`. Optional failures remain warnings. Neither collection nor packet construction calls app-server RPC, shell commands, or a Codex turn.

Only Read Only tasks can start a Bridge, and the workspace root is validated against the same forbidden-root policy used elsewhere. The app exposes recent unfinished tasks and restores the latest on page load; waiting tasks retain their original request packet for review. Startup recovery handles stale `PROCESSING_RESPONSE` tasks from an earlier process exactly once and moves them to `HOLD`; ordinary reads such as snapshot/get/recent do not mutate Bridge state. Pending v1 records are never converted automatically and appear as restart-required. These Bridge operations remain local-only: they do not invoke `thread/start`, `turn/start`, Workspace Write, Ultra, or a live Codex run.

## Asset Catalog, Phase 1

Asset Catalog Phase 1 is a local, metadata-only inventory for an explicitly registered Source Root. A source gets an internal UUID and a user-facing alias; its absolute root is stored only in SQLite and is never returned by the HTTP API, UI, logs, or Bridge packets. Registration requires an existing absolute directory and rejects forbidden-root relationships (`E:\`, `E:\.codex`, parents, and descendants), symlinks, junctions, and other reparse points.

Scanning uses iterative `os.scandir` with `follow_symlinks=False`. It records only project-relative path, case-folded path key, extension, size, `mtime_ns`, filesystem ID, extension-derived asset kind, scan generation, and a Phase-1 `QUEUED` fingerprint marker. It does not open source files, calculate any full-file SHA-256, inspect AssetBundle/FBX/PMX/textures, or call shell commands, app-server RPC, `thread/start`, or `turn/start`. `bytes_indexed` is the sum of metadata sizes; `content_bytes_read` remains zero.

The first scan marks files `ADDED`; later scans mark stable metadata `UNCHANGED`, changed size/mtime/file ID `MODIFIED`, and absent prior entries `MISSING`. A newly discovered file with matching stable metadata to a missing prior entry is marked `MOVED_CANDIDATE`; it is never auto-confirmed and the old record is retained. Case-insensitive collisions and links/junctions are `REJECTED`. Writes are committed in batches of at most 500 entries. An interrupted scan retains its pending directory cursor and can resume; only one scan per source is allowed at a time. Catalog entry IDs are intentionally only future Inspector inputs—they are not automatically included in Evidence or Web GPT packets.
## Targeted Format Probe, Phase 2

Targeted Format Probe Phase 2 accepts only `catalog_entry_id` values, never raw user paths. For each selected entry it revalidates the registered source root, resolves the catalog-relative file without following symlinks, junctions, or other reparse points, compares current `size`, `mtime_ns`, and filesystem ID against the Catalog snapshot before reading, and rejects stale entries with `STALE_CATALOG_ENTRY` so the user must rescan first.

Probe reads are capped at 50 entries per request and 128KB per file, although the current detector registry samples only a bounded prefix window. The result stores the Catalog asset kind separately from the probe-derived asset kind, the detector version, `bytes_read`, a SHA-256 over only the sampled bytes, confidence-scored format candidates, extension match status, and the single next Inspector hint (`UNITY_BUNDLE`, `PMX`, `FBX`, `GLTF`, `TEXTURE`, `ARCHIVE`, `AUDIO`, `EXECUTABLE`, or `NONE`). `full_parse_allowed` remains `false` in this phase.

The registry recognizes UnityFS/Raw/Web bundles, PMX/PMD, FBX binary/ASCII, GLB/glTF, PNG/JPEG/DDS/KTX1/KTX2/WEBP/BMP/TIFF, ZIP/7z/RAR/GZIP/XZ, PE/ELF, and WAV/OGG/FLAC/MP3 from strong signatures only. Weak-extension formats such as TGA are never confirmed from the extension alone. If the probe sees conflicting or insufficient evidence, `detected_format` remains `UNKNOWN`; a mismatch does not trigger any rename, rewrite, or automated Evidence attachment. Like the Catalog, Phase 2 is local-only and does not call app-server RPC, `command/exec`, `thread/start`, or `turn/start`.

Phase 2 cache reuse is intentionally conservative. Before any cache lookup, the app validates current Catalog metadata, reads only the detector-sized bounded sample, hashes just that sample, and builds the cache identity from `size`, `mtime_ns`, `file_id`, and `sample_sha256`. Only a prior `COMPLETED` result with the same identity is reusable; `FAILED`, `REJECTED`, and `STALE` attempts never become permanent cache entries and can be retried against the same file state. Each probe attempt is numbered and timestamped, and app startup atomically recovers orphaned `PENDING`/`PROBING` rows to `FAILED/probe_interrupted`.

Confidence and `next_inspector` are also conservative. `next_inspector` is assigned only when exactly one detector reaches `HIGH` confidence. Structural checks now validate GLB version/declared length, bounded glTF JSON `asset.version`, PMX/PMD header versions, BMP size/offset/DIB fields, and MP3 frame-header fields; weak evidence such as a bare FBX ASCII banner, fake `BM`, fake `Pmd`, fake `FF E0`, malformed glTF JSON, or malformed GLB remains `MEDIUM` or `UNKNOWN` so downstream Inspector and Codex tokens are not wasted on a bad guess.
