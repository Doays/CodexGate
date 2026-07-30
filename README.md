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

### WSL2 + bubblewrap preflight

The optional `WSL2_BWRAP` backend is a separate, fail-closed preflight. The user must type and save one WSL distribution name; Codex Gate never selects, installs, or configures a distribution, `bwrap`, Python, or Codex. It first performs a fixed `HOST_CHECK` (`wsl.exe --list --verbose`) for WSL2 and the selected distro, then one fixed `DISTRO_QUERY` (`wsl.exe -d <selected> --exec /usr/bin/python3 -I -S -c <embedded code>`). The embedded code reads distro/Python metadata and invokes only `/usr/bin/bwrap --version` with a three-second timeout. HOST_CHECK has a 10-second limit; DISTRO_QUERY allows 30 seconds for WSL cold start; each captures at most 8 KB and records only sanitized stage codes and timings. A canonical one-line JSON response with unknown keys, extra lines, or invalid UTF-8 is rejected. Successful preflight metadata has its own five-minute cache, separate from the 30-minute canary cache. The user-only `config_hash` is stored separately from a canonical `tool_fingerprint` (which includes WSL2, distro ID/version, Python, bwrap presence/version, and probe version); the cache key combines all three. Raw stdout/stderr and absolute paths are never stored or shown.

For the fixed canary, only the Windows Capsule directory is translated with `wslpath` and bound read-only at `/work`. bubblewrap uses `--unshare-all`, a separate network namespace, read-only runtime binds (`/usr`, `/bin`, `/lib`, `/lib64`, `/etc`), and a `tmpfs` `/tmp`; it does not bind `/mnt`, Windows user folders, or Catalog Source Roots. The canary must read `/work`, fail to read outside/host-mount targets, fail to write the Capsule, write and delete in `/tmp`, and fail to reach a local loopback listener. Duplicate or unexpected markers, ordinary failures, timeouts, and output overflow are `ERROR`; visible host reads, writes, or network access become `UNSAFE_HOST_FS`, `UNSAFE_WRITE`, or `UNSAFE_NETWORK`. A passing result is only `SAFE_CANDIDATE`, cached for the same configuration and tool fingerprint for 30 minutes, and **still never unlocks live execution**. The Token Ledger records preflight count/time separately from canary count/time, with zero tokens and zero app-server RPC calls. The UI reports only status, sanitized error codes, and whether the environment invalidated a cached result; tool version strings are not exposed.

### Sealed WSL Codex Runtime, Phase 0

Phase 0 prepares, but does not start, a WSL-native Codex runtime. The user explicitly selects one exact binary path under `/usr/local/bin/codex` or `/home/<user>/.local/bin/codex`; there is no discovery, `PATH` fallback, installer, or automatic version/schema update. The fixed direct-argv preflight checks only regular-file status, non-symlink status, executable mode, binary SHA-256, and `codex --version`. It accepts exactly `codex-cli 0.145.0`. Directory, symlink, non-executable, malformed, and version-mismatched selections fail closed. The selected path remains in the local configuration only and is never returned by the API or UI.

For a future execution, the app computes an immutable private bubblewrap launch spec and its hash: it binds a supplied Capsule read-only at `/work`, fixes the working directory to `/work`, uses only read-only runtime binds, and provides tmpfs `/tmp`, `/runtime-state`, and a fresh `/home/codex`. It clears inherited Windows and WSL environment values and allows only fixed `PATH`, `HOME`, `TMPDIR`, and `LANG`. `/mnt`, Windows user folders, Catalog Source Roots, and the data root are absent from the spec; network remains unshared. The runtime fingerprint includes the binary digest, fixed version, WSL isolation cache key, and runtime policy version. No credentials, API key, argv, environment value, or absolute binary path is exposed.

Because Phase 0 deliberately has no sealed authentication or model egress design, a binary that passes validation is recorded as `EGRESS_UNCONFIGURED` with an internal `READY_CANDIDATE` preflight signal. Its only permitted Codex invocation is the fixed `--version` metadata check; it never starts `app-server`, login, account, or a model turn, and it does not unlock the Windows app-server path, Workspace Write, Ultra, or live runs. Local runtime-preflight count and duration are the only Token Ledger values; tokens and app-server RPC calls remain zero.

Runtime identity payloads use `runtime-identity-v1`. A successful `EGRESS_UNCONFIGURED` row must contain the binary SHA-256, runtime fingerprint, launch-spec hash, current isolation cache key, and fail-closed flags. Older rows missing any of these fields are read-only `BLOCKED/runtime_identity_incomplete` records; the app never guesses or backfills a digest. Only a subsequent official preflight can atomically replace the legacy row with a complete identity, and API/UI snapshots still omit binary paths, argv, environments, and raw preflight output.

### Sealed Egress Contract Phase 1

Phase 1 creates an immutable, local-only future-egress contract; it does not start a relay, broker, socket listener, Codex process, DNS lookup, or network request. The only provider is `codexgate-sealed`, configured in ephemeral `CODEX_HOME/config.toml` bytes with `wire_api = "responses"`, `requires_openai_auth = false`, `env_key = "CODEXGATE_EPHEMERAL_TOKEN"`, no WebSockets, and zero request or stream retries. The config bytes are not stored: SQLite retains only their SHA-256 and a closed snapshot of the permitted fields. Built-in `openai`, `openai_base_url`, and proxy environment variables are not part of this path.

The contract permits exactly `http://127.0.0.1:8788/v1` inside the sandbox and one future Unix-socket boundary at the broker. That relay has no DNS, internet, or alternative socket output. The future broker permits only `POST /v1/responses`, enforces 256 KB request and 2 MB response caps with a 120-second timeout, rejects CONNECT, redirects, absolute-form targets, and arbitrary `Host` values, and strips caller `Authorization`, `Cookie`, and `Proxy-*` headers. A future broker may inject authentication outside this contract; no token, credential, raw request, or raw response is stored or logged here.

The contract hash binds the runtime fingerprint, WSL isolation cache key, binary SHA-256, provider-config SHA-256, and contract policy version. Any binding change makes it unusable. With relay, broker, and authentication intentionally absent, the persisted final state is `AUTH_UNCONFIGURED`; runtime start, live execution, Workspace Write, and Ultra all remain locked. Token Ledger records only local contract construction count and duration, with zero tokens and zero app-server RPC calls.

### Sealed Egress Local Harness Phase 2

An explicit contract creation stores one immutable SQLite instance. Its preview hash must equal the stored contract hash, and an identical runtime, isolation, binary, provider, and policy identity returns the same instance rather than creating a duplicate. The harness is bound to that instance and is `READY` only while the current runtime fingerprint, isolation key, and contract hash still match.

Phase 2 supplies a deterministic **fake runner only**. It models a bubblewrap-local `127.0.0.1:8788` relay forwarding exactly one `POST /v1/responses` request to one AF_UNIX broker boundary. The broker strips `Authorization`, `Cookie`, and `Proxy-*`, rejects CONNECT, absolute-form targets, redirects, other hosts/methods/paths, and enforces the sealed 256 KB request, 2 MB response, and 120-second contract limits. Its fake Responses-shaped result has a canonical deterministic hash. It never opens an actual Unix socket, loopback listener, WSL process, bwrap process, Codex process, DNS lookup, or external connection.

The modeled launch policy clears the environment, allows only fixed `PATH`, `HOME`, `TMPDIR`, and `LANG`, uses an execution-private socket-directory placeholder only, and never binds `/mnt`, a Windows path, a Source Root, or the data root. Harness summaries retain only status, request/response sizes, response hash, counters, duration, and sanitized errors; they retain no body, credential, argv, socket path, or raw output. Startup converts orphaned `RUNNING` summaries to `ERROR/harness_interrupted`; matching concurrent requests are single-flight. A passing fake harness does not alter `AUTH_UNCONFIGURED`: Runtime start, ordinary live runs, Workspace Write, and Ultra remain locked.

### Sealed Egress Local Harness Phase 3

Phase 3 adds, but does not select, a fixed-argv WSL supervisor runner. It accepts only a stored immutable Contract instance whose preview hash, runtime fingerprint, isolation cache key, binary digest, provider configuration digest, and Ubuntu selection still match immediately before launch. A preview object alone is blocked. The supervisor is fixed Python bytes invoked once through `wsl.exe -d Ubuntu --exec /usr/bin/python3 -I -S -u -c`; it receives no user command, path, environment, request body, credential, or proxy setting.

The prepared topology has two separate `bwrap --unshare-all --clearenv` processes: an AF_UNIX-only broker with one private socket, and a relay/client sandbox with only that socket directory read-only, a small `/work` fixture read-only, and one sandbox-local `127.0.0.1:8788` listener. Both use tmpfs HOME and `/tmp`; `/mnt`, Windows paths, Source Roots, the data root, and user HOME are absent. The client allows exactly one `POST /v1/responses`; second connections, extra frames, sensitive headers at the broker, non-loopback hosts, other paths, methods, redirects, and absolute-form targets are policy violations.

The supervisor returns only one base64url canonical result frame containing sizes, hashes, counters, and sanitized status. Stdout and stderr remain separate and jointly limited to 8 KB; startup, request, and total limits are 10, 15, and 30 seconds. The runner kills both process trees and requires socket, fixture, and temporary-directory cleanup before it can pass. Phase 3 tests use a fake WSL supervisor only: no WSL, bubblewrap, AF_UNIX, network, Codex, app-server, or model process is executed, and `AUTH_UNCONFIGURED`, Runtime start blocking, Workspace Write, Ultra, and ordinary live-run locks remain unchanged.

### Actual WSL Harness Gate Phase 3.1

An immutable Contract can now be created only while the current `SAFE_CANDIDATE` Canary has at least the 30-second expected harness duration plus five minutes remaining. The app derives a Repro key from the current `config_hash`, `tool_fingerprint`, and fixed Repro protocol version; this key is deliberately different from the Isolation cache key. The matching Repro row must be `SAFE_REPRODUCIBLE` with requested/completed/successful counts of 10/10/10, the same environment hashes, and a valid result hash. The Contract identity binds the Repro version, derived key, and result hash, and the actual runner checks all of them again immediately before any future launch.

Fake and actual results use separate SQLite identities: `contract_hash + runner_kind + runner_version`. Thus `FAKE PASSED` can never be reused as `WSL PASSED`, and a runner-version change creates a separate result. The existing fake endpoint remains `/api/isolation/wsl/egress-harness`. The actual endpoint is separate and requires a locally generated one-time arm nonce, whose plaintext is never stored; the nonce is contract- and runner-bound, expires after five minutes, and cannot be reused. Phase 3.1 originally kept this endpoint hard-disabled; Phase 3.3 replaces that static switch with the stricter explicit two-minute execution-window protocol documented below. Local API examples use only `http://127.0.0.1:8787`; `testserver`, `0.0.0.0`, and external hosts remain rejected. Authentication, network egress, SAFE_CAPSULE_ONLY, Runtime start, live execution, Workspace Write, and Ultra all remain locked.

### Actual WSL Harness Implementation Seal Phase 3.2

The WSL runner now has one implementation source for execution and review: shared common bubblewrap arguments plus broker, relay/client, and supervisor argv templates. Both child launch specs and the fixed supervisor materialize those exact templates, including the real `/usr/bin/python3 -I -S -u -c <fixed code>` form. SHA-256 values are computed for the supervisor code, broker child code, relay child code, and canonical argv-template set; their canonical aggregate is `runner_implementation_hash`, and the WSL runner version is derived from that hash. Any one-byte code or argv change therefore creates a new runner version and implementation identity.

Harness storage and arm binding use `contract_hash + runner_kind + runner_version + runner_implementation_hash`. Migration assigns the preserved fake implementation hash to legacy fake rows and a fail-closed zero hash to old WSL rows that lacked a seal, so an old WSL `PASSED` result or arm cannot satisfy the current runner. The strict result frame includes the full implementation hash, and a mismatch is `POLICY_VIOLATION`.

Socket evidence is role-specific rather than a misleading global `tcp=0`. The broker permits exactly one pathname AF_UNIX listener and zero INET, UDP, or DNS attempts. The relay/client permits exactly one broker AF_UNIX connection and one `127.0.0.1` TCP listener/connection pair; non-loopback, UDP, and DNS attempts must remain zero. Host, method, path, sensitive-header removal, canonical frame, size, timeout, and cleanup checks remain unchanged. This phase still uses fake process runners only and does not execute WSL, bwrap, AF_UNIX, network, Codex, app-server, or a model turn.

### Actual WSL Harness Execution Window Phase 3.3

Phase 3.3 has no persistent enable flag. Its default state is `DISABLED`; only a button request from `127.0.0.1` with the identical local `Origin` can open an `ARMED` execution window. The window lasts exactly two minutes, cannot be extended, and returns two plaintext one-time nonces only to that response. SQLite stores SHA-256 digests only. A restart turns any remaining `ARMED` record into `EXPIRED`.

The window binds a stored immutable Contract ID/hash, WSL runner kind/version/implementation hash, the current isolation config/tool/cache identity, and the current 10/10/10 `SAFE_REPRODUCIBLE` Repro version/key/result hash. Both Canary freshness (at least five minutes remaining) and that complete Repro proof are required while arming, and are checked again immediately before the actual runner would be selected. A changed binding consumes the window and blocks the request. The execution endpoint requires both the new window nonce and the existing arm nonce; it atomically consumes both before any runner call, so retries cannot reuse either capability.

Only the sealed `WSLEgressHarnessRunner` identity is accepted by this endpoint; fake identities are a policy violation and cannot become actual evidence. The window grants no Runtime, `SAFE_CAPSULE_ONLY`, normal live-run, Workspace Write, Ultra, network, or authentication permission. This implementation is tested with a no-I/O process double only; it does not execute WSL, bubblewrap, AF_UNIX, Codex, app-server, or a model turn.

### Sealed Offline Codex Process Canary Phase 4.0

Phase 4.0 defines a separate, two-minute, one-use offline Codex Canary window. It requires a complete `runtime-identity-v1`, the current immutable `AUTH_UNCONFIGURED` Contract, an exact current `WSL_SUPERVISOR` Harness `PASSED` record, a fresh isolation Canary, and the matching `SAFE_REPRODUCIBLE` 10/10/10 result. The Canary runner implementation hash canonically binds its fixed broker, relay/Codex, and supervisor program bytes, fixed Codex argv, fixed prompt, and deterministic fake Responses result; changing any of those inputs creates a different runner identity and prevents old `PASSED` results or capabilities from being reused.

The modeled process arrangement is one read-only broker bubblewrap and one sealed relay/Codex bubblewrap. The latter has a throwaway tmpfs `CODEX_HOME` whose only config is the immutable Contract TOML bytes, a fixed `/work`, and no inherited environment, host mounts, credentials, or general network. It permits exactly one fixed `POST /v1/responses`, no WebSocket, second request, model change, tool call, command execution, file change, retry, reroute, or network tool. A valid result requires the exact success marker, exit code zero, a 45-second limit, and at most 16 KB combined output; raw prompt, response, config, stdout, stderr, paths, and token values are never stored.

The production runner is deliberately `DISABLED` in this phase, so arm/run APIs fail closed and no WSL, bubblewrap, Codex, socket, external network, app-server RPC, or model request can start. Tests use only an in-memory deterministic runner. Plan/fake events use `LOCAL_ESTIMATE`/`ESTIMATED`; only a future real runner may emit `LOCAL_OBSERVED`/`OBSERVED` process counts and monotonic duration. Provider token columns remain null, external tokens and RPC are zero, and reports remain `NOT_COMPARABLE`; no planned process count is included in measured totals. A future successful Canary would still leave Runtime start, ordinary live runs, `SAFE_CAPSULE_ONLY`, Workspace Write, and Ultra locked.

Phase 4.1 adds a separate **Offline Canary Execution Permit** without adding a durable enable switch. Its default state is `DISABLED`; only a `127.0.0.1` request with the identical local `Origin` can mint one two-minute Permit. SQLite stores only the Permit nonce SHA-256. The Permit binds the complete `runtime-identity-v1`, immutable Contract ID/hash, exact actual Harness `PASSED` identity, fresh Canary plus matching `SAFE_REPRODUCIBLE` 10/10/10 proof, and the sealed Offline Canary runner implementation hash. A valid Permit can arm one existing Canary window, but does not make the runner globally enabled.

The execution request atomically consumes the Permit nonce and Canary-window nonce before it rechecks the binding or could select the runner. A changed binding is recorded as `execution_binding_changed`; either capability cannot be retried. App restart expires any remaining Permit. Only the concrete sealed WSL Canary runner identity is accepted—fake runner injection is a policy violation. Permit issuance and consumption start no process; a pre-spawn denial records `LOCAL_OBSERVED` with `local_processes = 0`, null provider tokens, zero external model requests, and zero app-server RPCs. The currently sealed production runner remains disabled, so this phase still performs no WSL, bwrap, Codex, socket, DNS, or model execution.

### Sealed Offline Codex Canary One-Shot Runner Phase 4.2

Phase 4.2 keeps the ordinary Canary endpoint fail-closed as
`codex_canary_execution_disabled`. A separate local IPv4/same-Origin
one-shot endpoint is the only route that can select the concrete
`WSLCodexProcessCanaryRunner`. It accepts no user command, path, model, prompt,
or argv. The Permit and Canary-window nonce hashes, the complete Runtime,
Contract, actual Harness, Canary, Repro, and runner implementation identities
are rechecked and atomically claimed in one SQLite `BEGIN IMMEDIATE`
transaction. The claim stores only identifiers and SHA-256 values; both
plaintext nonces are immediately unrecoverable.

No runner object or executor is materialized before a claim reaches `RUNNING`.
The concrete runner receives only its sealed launch specification and may make
at most one spawn attempt; retry, fallback, reroute, resume, and a second spawn
are prohibited. A changed binding is consumed and reported as
`execution_binding_changed` before a process can start. Restart recovery turns
orphaned `CLAIMED`/`RUNNING` claims into `ERROR/canary_interrupted`. The Phase
4.2 production factory deliberately has no executor, so the one-shot endpoint
still records a zero-process observed block instead of starting WSL or Codex.
Tests inject only a deterministic no-I/O executor behind the same concrete
runner class. Any actual future spawn records only the count that started and
monotonic duration as `LOCAL_OBSERVED`; provider tokens stay null, fake usage
is ignored, and external-model and app-server-RPC counters remain zero.

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
## Token Savings Ledger

## WSL2 reproducibility check

After a sanitized `SAFE_CANDIDATE` WSL2_BWRAP result exists, the local-only repeatability check can run a fixed workload ten times. Each attempt receives a fresh capsule and bwrap process, uses an allowlisted environment with `/work` as its read-only working directory, and checks capsule reads, host/outside reads, writes, temporary-file handling, and loopback networking. No user command, source root, Windows mount, app-server RPC, or model turn is involved.

Only the redacted count, final status, canonical result hash, duration, and sanitized error code are stored. Raw output, fixture contents, paths, and canaries never leave the process. A mismatch is `NONDETERMINISTIC`; boundary failures are classified as `UNSAFE_HOST_FS`, `UNSAFE_WRITE`, or `UNSAFE_NETWORK`, and timeout/marker/process failures are `ERROR`. SAFE_CANDIDATE itself is unchanged and live execution remains locked in every state. Concurrent requests for the same configuration are single-flight, and an orphaned `RUNNING` record is recovered as `ERROR/probe_interrupted` at startup.

The child workload emits exactly one `CODEXGATE_REPRO_V1:<base64url canonical JSON>` frame using `os.write`; it runs with `-I -S -u`. Host stdout and stderr are captured separately. Surrounding blank lines and CRLF/LF are normalized, but missing, duplicate, or additional non-empty frame lines, non-canonical JSON, invalid base64url, wrong iteration, and fixture mismatches are rejected with sanitized protocol codes. stderr warnings contribute only their byte length to diagnostics.

The fixture is produced once per attempt by `build_repro_fixture_bytes()`, written with binary `wb` plus flush/fsync, and hashed directly from those immutable bytes. The child opens the shared fixed relative fixture path in `rb`; iteration is only a frame field. The write-denial path is separate, and the stable result hash excludes iteration while retaining the fixture hash and six boundary outcomes.

Token Savings Ledger Phase 1 records observed, imported, and estimated usage signals without storing raw prompts, raw responses, or full logs.

It tracks ledger runs, usage events, and manually imported baselines, then exports a JSON or Markdown summary through the `/api/token-ledger/*` endpoints.

## Contract preview and immutable instances

The egress-contract preview is a pure read operation. It recomputes a
`current_binding_hash` and `preview_hash` from the complete runtime identity
(identity version, runtime and launch-spec digests, binary digest), current
Isolation identity, Repro proof, provider configuration, and policy version.
It never grants Runtime or Harness permission and never writes a database row.

The older singleton table is retained as an audit trail for blocked outcomes,
but a blocked snapshot is never returned as the current preview after the
environment changes. Immutable instances live in their separate instance table
and remain bound to the identity with which they were created. A creation
request must provide the current `expected_preview_hash`; the transaction
recomputes the binding and rejects stale values with `preview_stale`. Matching
identity and hash requests are idempotent and return the existing instance.
The HTTP API exposes `GET /api/isolation/wsl/egress-contract/preview` and
requires the hash in the POST body. Authentication remains unconfigured and
all starts remain locked.

If no successful live run has been recorded, the report shows `실제 토큰 절감 미측정`.
