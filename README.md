# Codex Gate

Codex Gate is a local control plane that separates ChatGPT-style planning from Codex execution. It keeps model choice, approval policy, workspace bounds, and run state under one UI.

## What it does

- Connects to `codex app-server --stdio`
- Loads the installed Codex version and generated JSON schema
- Starts runs in `thread/start` and `turn/start`
- Keeps Workspace Write locked in this release
- Streams approval requests to the UI over SSE
- Stores tasks and artifacts in SQLite under the data root

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

## Data root

The app stores its local state under `CODEX_GATE_HOME`.

- Default: `C:\Users\<you>\CodexGate`
- Override with: `CODEX_GATE_HOME`

## Forbidden roots

Workspace access is blocked for forbidden roots before preflight and run execution.

- Default forbidden root: `E:\.codex`
- Override or add more with: `CODEX_GATE_FORBIDDEN_ROOTS`

## Security notes

- Only `127.0.0.1` and `localhost` are accepted as `Host`
- If `Origin` is present, it must match the same local origin
- `project_id` must be a safe slug or UUID
- Artifact names are limited to an internal allowlist
- Workspace Write stays locked until the write-validation step is explicitly enabled in a later release
