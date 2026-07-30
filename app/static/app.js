const $ = (id) => document.getElementById(id);

let catalog = [];
let currentRun = null;
let currentPlan = null;
let currentCapsule = null;
let isolationStatus = "UNKNOWN";
let wslIsolationStatus = "UNCONFIGURED";
let wslRuntimeStatus = "UNCONFIGURED";
let wslEgressStatus = "UNCONFIGURED";
let wslHarnessStatus = "BLOCKED";
let actualWSLHarnessStatus = "NOT RUN";
let actualWSLHarnessArm = null;
let codexProcessCanaryPermit = null;
let codexProcessCanaryArm = null;
let stream = null;
let planExpiryTimer = null;
let currentBridge = null;
let bridgeManualMode = null;
let currentCatalogSource = null;
let selectedCatalogEntries = new Set();

function say(message, isError = false) {
  const node = $("message");
  node.textContent = message;
  node.style.color = isError ? "#ff9b8e" : "";
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "Request failed.");
  }
  return data;
}

function option(value, label, selected = false) {
  const node = document.createElement("option");
  node.value = value;
  node.textContent = label;
  node.selected = selected;
  return node;
}

function slugify(value) {
  return value
    .trim()
    .normalize("NFKD")
    .toLowerCase()
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function projectIdFromName(value) {
  const slug = slugify(value);
  return slug || crypto.randomUUID();
}

function loadModels(choices) {
  catalog = choices;
  const model = $("model");
  const previous = model.value;
  model.replaceChildren();

  if (!choices.length) {
    model.appendChild(option("", "No models connected", true));
    model.disabled = true;
    loadEfforts();
    return;
  }

  const selected = choices.find((entry) => entry.id === previous) || choices[0];
  for (const entry of choices) {
    model.appendChild(option(entry.id, entry.display_name, entry.id === selected.id));
  }
  model.disabled = true;
  loadEfforts();
}

function loadEfforts() {
  const selected = catalog.find((entry) => entry.id === $("model").value);
  const effort = $("effort");
  const efforts = (selected?.efforts || []).filter((value) => value !== "ultra");
  effort.replaceChildren();

  if (!efforts.length) {
    effort.appendChild(option("", "No supported efforts", true));
    effort.disabled = true;
    return;
  }

  const defaultEffort = selected?.default_effort || efforts[0];
  for (const value of efforts) {
    effort.appendChild(option(value, value, value === defaultEffort));
  }
  effort.disabled = true;
}

function formatReset(value) {
  if (typeof value !== "number") return "UNKNOWN";
  return new Date(value * 1000).toLocaleString();
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  row.appendChild(cell);
  return cell;
}

function renderAccount(overview) {
  const account = overview?.account || {};
  const limits = overview?.rate_limits || {};
  const primary = limits.rateLimits?.primary || null;
  const usage = overview?.usage || {};
  const used = typeof primary?.usedPercent === "number" ? `${primary.usedPercent}%` : "UNKNOWN";
  $("account-state").textContent = overview?.account_state || "UNKNOWN";
  $("account-auth").textContent = `${account.auth_mode || "UNKNOWN"} / ${account.plan_type || "UNKNOWN"}`;
  $("account-used").textContent = used;
  $("account-reset").textContent = formatReset(primary?.resetsAt);
  $("account-meta").textContent = `계정 rate-limit: ${limits.status || "UNKNOWN"}; 이메일: ${account.email_masked || "not stored"}; 모델별 잔여량이 아닙니다.`;
  const daily = Array.isArray(usage.daily) ? usage.daily : [];
  const tokens = daily.reduce((total, entry) => total + (Number.isFinite(entry.tokens) ? entry.tokens : 0), 0);
  $("usage-meta").textContent = usage.status === "AVAILABLE"
    ? `일별 토큰 사용량 ${daily.length}일 / ${tokens.toLocaleString()} tokens (일별 요약만 저장)`
    : "일별 토큰 사용량: UNKNOWN";
}

function renderCatalog(entries) {
  const body = $("model-catalog");
  body.replaceChildren();
  for (const entry of entries || []) {
    const row = document.createElement("tr");
    appendCell(row, `${entry.display_name || entry.id} (${entry.id})`);
    appendCell(row, (entry.efforts || []).join(" → ") || "UNKNOWN");
    appendCell(row, (entry.speed_tiers || []).map((tier) => tier.name || tier.id).join(", ") || "—");
    const statusCell = document.createElement("td");
    const select = document.createElement("select");
    for (const state of ["AVAILABLE", "LIMITED", "DEPLETED", "UNKNOWN", "DISABLED"]) {
      select.appendChild(option(state, state, state === entry.status));
    }
    select.onchange = async () => {
      try {
        const data = await api(`/api/models/${encodeURIComponent(entry.id)}/status`, {
          method: "POST",
          body: JSON.stringify({ status: select.value }),
        });
        renderCatalog(data.model_catalog);
        say(`Manual model status updated: ${entry.id} → ${select.value}`);
      } catch (error) {
        select.value = entry.status;
        say(error.message, true);
      }
    };
    statusCell.appendChild(select);
    row.appendChild(statusCell);
    body.appendChild(row);
  }
}

function renderRoutePreview(result) {
  const root = $("router-result");
  root.replaceChildren();
  root.classList.toggle("hold", result.status === "HOLD");
  const table = document.createElement("table");
  table.className = "catalog-table";
  const head = document.createElement("thead");
  const header = document.createElement("tr");
  for (const text of ["상태", "웹 GPT 추천", "최종 미리보기", "후보 사다리", "사유", "반영 입력"]) {
    const cell = document.createElement("th");
    cell.textContent = text;
    header.appendChild(cell);
  }
  head.appendChild(header);
  const body = document.createElement("tbody");
  const row = document.createElement("tr");
  const recommendation = result.recommendation || {};
  const final = result.final || {};
  appendCell(row, result.status || "UNKNOWN");
  appendCell(row, `${recommendation.model || "—"} / ${recommendation.effort || "—"}`);
  appendCell(row, final.model ? `${final.model} / ${final.effort}` : "HOLD");
  appendCell(row, (result.candidate_ladder || []).map((candidate) => `${candidate.model}${candidate.effort ? `/${candidate.effort}` : ""} [${candidate.status}]: ${candidate.selection_reason}`).join("\n") || "—");
  appendCell(row, [...(result.downgrade_reasons || []), ...(result.hold_reasons || []), ...(result.warnings || [])].join(" ") || "No change.");
  const policy = result.policy_input || {};
  const maximum = result.account_usage_evidence?.maximum_used_percent;
  appendCell(row, `계정 ${result.account_state || "UNKNOWN"}${typeof maximum === "number" ? ` (${maximum}%)` : ""}\n파일 ${policy.file_count ?? "—"}\n테스트 ${policy.has_tests ? "있음" : "없음"}\n${policy.read_only ? "Read Only" : "Write"}`);
  body.appendChild(row);
  table.append(head, body);
  root.appendChild(table);
}

async function previewRouter() {
  try {
    const decision = JSON.parse($("decision").value);
    const fileCount = new Set(Array.isArray(decision.allowed_files) ? decision.allowed_files : []).size;
    const data = await api("/api/router/preview", {
      method: "POST",
      body: JSON.stringify({
        task_class: $("router-task-class").value,
        risk: $("router-risk").value,
        read_only: $("permission").value === "read-only",
        file_count: fileCount,
        has_tests: Boolean(currentPlan?.validation_evidence?.has_tests),
        web_recommendation: { model: $("model").value, effort: $("effort").value },
        parallel_audit: $("router-parallel").checked,
        independent_axes: Number.parseInt($("router-axes").value, 10) || 0,
        explicit_ultra_approval: $("router-ultra-approval").checked,
      }),
    });
    renderRoutePreview(data);
    say(data.status === "HOLD" ? "Router preview is HOLD; no execution settings changed." : "Router preview generated; execution settings remain unchanged.", data.status === "HOLD");
  } catch (error) {
    say(error.message, true);
  }
}

async function connect() {
  try {
    say("Connecting to Codex app-server...");
    const data = await api("/api/connect", { method: "POST" });
    loadModels(data.choices);
    renderAccount(data.account_usage);
    renderCatalog(data.model_catalog);
    renderIsolation(data.isolation);
    renderWSLIsolation(data.wsl_isolation);
    renderWSLCodexRuntime(data.wsl_codex_runtime);
    renderSealedEgressContract(data.sealed_egress_contract);
    renderSealedEgressHarness(data.sealed_egress_harness);
    renderActualWSLEgressHarness(data.actual_wsl_egress_harness);
    renderCodexProcessCanary(data.codex_process_canary);
    renderTokenLedger(data.token_ledger || {});
    $("connection-dot").classList.add("live");
    $("connection-text").textContent = `${data.choices.length} models connected`;
    $("codex-meta").textContent = `${data.codex_version || "version unavailable"} · ${data.codex_path || "path unavailable"}`;
    const writeOption = [...$("permission").options].find((option) => option.value === "workspace-write");
    if (writeOption) {
      writeOption.disabled = !data.workspace_write_available;
    }
    if (!data.workspace_write_available && $("permission").value === "workspace-write") {
      $("permission").value = "read-only";
    }
    $("create-plan").disabled = false;
    updateExecuteState();
    say(
      data.workspace_write_available
        ? "Connected. Workspace Write is ready."
        : "Connected. Workspace Write remains locked while schema checks are pending.",
      !data.workspace_write_available,
    );
  } catch (error) {
    say(error.message, true);
  }
}

function planIsExecutable() {
  return false;
}

function renderIsolation(result) {
  isolationStatus = result?.status || "UNKNOWN";
  $("isolation-status").textContent = isolationStatus;
  let outside = "outside read failed or was not confirmed";
  if (result?.outside_read_succeeded === true) {
    outside = "outside read succeeded";
  } else if (result?.outside_denied_explicitly === true) {
    outside = "outside read was explicitly denied";
  }
  const errorCode = result?.error_code ? `; code=${result.error_code}` : "";
  $("isolation-result").textContent = `${isolationStatus}; ${outside}${errorCode}. Live runs stay locked in this release.`;
  updateExecuteState();
}

function renderWSLIsolation(result) {
  wslIsolationStatus = result?.status || "UNCONFIGURED";
  $("wsl-isolation-status").textContent = wslIsolationStatus;
  if (result?.distro) $("wsl-isolation-distro").value = result.distro;
  const environmentText = result?.environment_changed ? " Environment changed; cached result was invalidated." : "";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  $("wsl-isolation-result").textContent = `${wslIsolationStatus}.${code}${environmentText} Live runs remain locked in this release.`;
  updateExecuteState();
  const reproButton = $("run-wsl-isolation-repro");
  if (reproButton) reproButton.disabled = wslIsolationStatus !== "SAFE_CANDIDATE";
}

function renderWSLRepro(result) {
  const node = $("wsl-isolation-repro-result");
  if (!node) return;
  const status = result?.status || "UNKNOWN";
  const completed = Number(result?.completed_runs || 0);
  const success = Number(result?.success_count || 0);
  node.textContent = `Repeatability: ${success}/${completed || 10} successful; final status ${status}. Live runs remain locked.`;
}

function renderWSLCodexRuntime(result) {
  wslRuntimeStatus = result?.status || "UNCONFIGURED";
  const statusNode = $("wsl-runtime-status");
  const detailNode = $("wsl-runtime-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = wslRuntimeStatus;
  const configured = result?.binary_configured === true ? "configured" : "not configured";
  const version = result?.version_match === true ? "matches 0.145.0" : "not matched";
  const isolation = result?.isolation_match === true ? "matches WSL isolation" : "isolation not matched";
  const fingerprint = result?.runtime_fingerprint ? "recorded" : "not available";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  detailNode.textContent = `Binary ${configured}; version ${version}; runtime fingerprint ${fingerprint}; ${isolation}; egress remains blocked.${code} Codex start stays locked.`;
}

function renderSealedEgressContract(result) {
  wslEgressStatus = result?.status || "UNCONFIGURED";
  const statusNode = $("wsl-egress-status");
  const detailNode = $("wsl-egress-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = wslEgressStatus;
  const endpoint = result?.endpoint_type || "UNCONFIGURED";
  const contract = result?.contract_hash ? "recorded" : "not recorded";
  const relay = result?.relay_status || "RELAY_MISSING";
  const broker = result?.broker_status || "BROKER_MISSING";
  const auth = result?.auth_status || "AUTH_UNCONFIGURED";
  const lifecycle = result?.reused ? " Existing Contract reused." : result?.created ? " New Contract created." : "";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  detailNode.textContent = `Endpoint ${endpoint}; contract hash ${contract}; relay ${relay}; broker ${broker}; auth ${auth}.${lifecycle}${code} Network and Codex start remain locked.`;
}

function renderSealedEgressHarness(result) {
  wslHarnessStatus = result?.status || "BLOCKED";
  const statusNode = $("wsl-harness-status");
  const detailNode = $("wsl-harness-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = `FAKE ${wslHarnessStatus}`;
  const hash = result?.contract_hash ? "immutable contract matched" : "no runnable contract";
  const resultHash = result?.response_hash ? "deterministic response recorded" : "no response body stored";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  detailNode.textContent = `FAKE ${wslHarnessStatus}; ${hash}; ${resultHash}. This result is never reused as WSL proof.${code}`;
  const button = $("run-wsl-egress-harness");
  if (button) button.disabled = wslHarnessStatus !== "READY";
}

function renderActualWSLEgressHarness(result) {
  actualWSLHarnessStatus = result?.status === "PASSED" ? "PASSED" : "NOT RUN";
  const statusNode = $("actual-wsl-harness-status");
  const detailNode = $("actual-wsl-harness-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = `WSL ${actualWSLHarnessStatus}`;
  const proof = result?.status === "READY" ? "current Canary and Repro proof matched" : "proof or contract not ready";
  const implementation = result?.runner_implementation_hash ? "runner implementation sealed" : "runner implementation unavailable";
  const window = result?.execution_window || { status: "DISABLED", remaining_seconds: 0 };
  const windowState = window.status || "DISABLED";
  const remaining = windowState === "ARMED" ? ` ${window.remaining_seconds || 0}s remaining.` : "";
  const binding = window.binding_hash ? ` Binding ${window.binding_hash.slice(0, 16)}…` : "";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  detailNode.textContent = `Actual WSL: ${actualWSLHarnessStatus}; ${proof}; ${implementation}. Window ${windowState}.${remaining}${binding}${code} The window authorizes one harness request only; Runtime and live execution stay locked.`;
  const armButton = $("arm-actual-wsl-egress-harness");
  const runButton = $("run-actual-wsl-egress-harness");
  if (armButton) armButton.disabled = result?.status !== "READY" || windowState === "ARMED";
  if (runButton) runButton.disabled = windowState !== "ARMED" || !actualWSLHarnessArm;
}

function renderCodexProcessCanary(result) {
  const statusNode = $("codex-process-canary-status");
  const detailNode = $("codex-process-canary-result");
  if (!statusNode || !detailNode) return;
  const status = result?.status || "DISABLED";
  const permit = result?.execution_permit || { status: "DISABLED", remaining_seconds: 0 };
  const window = result?.execution_window || { status: "DISABLED", remaining_seconds: 0 };
  const permitRemaining = permit.status === "ARMED" ? ` ${permit.remaining_seconds || 0}s remaining.` : "";
  const remaining = window.status === "ARMED" ? ` ${window.remaining_seconds || 0}s remaining.` : "";
  const implementation = result?.implementation_hash ? "implementation sealed" : "implementation not runnable";
  const code = result?.error_code ? ` Code: ${result.error_code}.` : "";
  statusNode.textContent = status;
  const claim = result?.execution_claim || { status: "DISABLED" };
  detailNode.textContent = `Offline Codex canary ${status}; ${implementation}. Permit ${permit.status || "DISABLED"}.${permitRemaining} Canary window ${window.status || "DISABLED"}.${remaining} One-shot claim ${claim.status || "DISABLED"}.${code} One local click authorizes at most one fixed fake-response check with external model tokens 0; Runtime and live execution remain locked.`;
  const permitButton = $("issue-codex-process-canary-permit");
  const armButton = $("arm-codex-process-canary");
  const runButton = $("run-codex-process-canary");
  if (permitButton) permitButton.disabled = result?.permit_ready !== true || permit.status === "ARMED";
  if (armButton) armButton.disabled = permit.status !== "ARMED" || window.status === "ARMED" || !codexProcessCanaryPermit;
  if (runButton) runButton.disabled = permit.status !== "ARMED" || window.status !== "ARMED" || !codexProcessCanaryPermit || !codexProcessCanaryArm;
}

async function runIsolationProbe() {
  try {
    $("run-isolation-probe").disabled = true;
    say("Testing app-server read isolation without starting a model turn...");
    const result = await api("/api/isolation/probe", { method: "POST" });
    renderIsolation(result);
    say(`Isolation probe recorded: ${result.status}. Live execution remains locked.`, result.status !== "SAFE_CANDIDATE");
  } catch (error) {
    say(error.message, true);
  } finally {
    $("run-isolation-probe").disabled = false;
  }
}

async function saveWSLIsolationConfig() {
  try {
    const data = await api("/api/isolation/wsl/config", {
      method: "POST",
      body: JSON.stringify({ distro: $("wsl-isolation-distro").value }),
    });
    $("wsl-isolation-distro").value = data.distro;
    say("WSL distribution saved. Run the fixed bwrap preflight when ready.");
  } catch (error) {
    say(error.message, true);
  }
}

async function runWSLIsolationProbe() {
  try {
    $("run-wsl-isolation-probe").disabled = true;
    say("Running fixed WSL2+bubblewrap canaries without an app-server or model turn...");
    const result = await api("/api/isolation/wsl/probe", { method: "POST" });
    renderWSLIsolation(result);
    say(`WSL isolation probe recorded: ${result.status}. Live execution remains locked.`, result.status !== "SAFE_CANDIDATE");
  } catch (error) {
    say(error.message, true);
  } finally {
    $("run-wsl-isolation-probe").disabled = false;
  }
}

async function runWSLIsolationRepro() {
  try {
    $("run-wsl-isolation-repro").disabled = true;
    say("Running the fixed 10-run WSL check without a model turn...");
    const result = await api("/api/isolation/wsl/repro", { method: "POST" });
    renderWSLRepro(result);
    say(`WSL repeatability check: ${result.status}. Live execution remains locked.`, result.status !== "SAFE_REPRODUCIBLE");
  } catch (error) {
    say(error.message, true);
  } finally {
    $("run-wsl-isolation-repro").disabled = wslIsolationStatus !== "SAFE_CANDIDATE";
  }
}

async function saveWSLCodexRuntimeConfig() {
  try {
    const value = $("wsl-runtime-binary").value;
    await api("/api/isolation/wsl/runtime/config", {
      method: "POST",
      body: JSON.stringify({ binary_path: value }),
    });
    $("wsl-runtime-binary").value = "";
    say("WSL Codex binary selection was saved privately. Validate metadata without starting Codex.");
  } catch (error) {
    say(error.message, true);
  }
}

async function runWSLCodexRuntimePreflight() {
  try {
    $("run-wsl-runtime-preflight").disabled = true;
    say("Validating the selected WSL binary metadata only; no Codex process will start...");
    const result = await api("/api/isolation/wsl/runtime/preflight", { method: "POST" });
    renderWSLCodexRuntime(result);
    say(`Sealed runtime validation: ${result.status}. Egress and Codex start remain locked.`, result.status !== "EGRESS_UNCONFIGURED");
  } catch (error) {
    say(error.message, true);
  } finally {
    $("run-wsl-runtime-preflight").disabled = false;
  }
}

async function createSealedEgressContract() {
  const button = $("create-wsl-egress-contract");
  try {
    button.disabled = true;
    say("Refreshing the sealed contract preview before creating an immutable instance...");
    const preview = await api("/api/isolation/wsl/egress-contract/preview");
    if (!preview.preview_hash) throw new Error(preview.error_code || "contract preview is not ready");
    const result = await api("/api/isolation/wsl/egress-contract", {
      method: "POST",
      body: JSON.stringify({ expected_preview_hash: preview.preview_hash }),
    });
    renderSealedEgressContract(result);
    renderSealedEgressHarness(await api("/api/isolation/wsl/egress-harness"));
    renderActualWSLEgressHarness(await api("/api/isolation/wsl/egress-harness/actual"));
    renderCodexProcessCanary(await api("/api/isolation/wsl/codex-process-canary"));
    const lifecycle = result.reused ? "Existing Contract reused." : result.created ? "New Contract created." : "";
    say(`Sealed egress contract: ${result.status}. ${lifecycle} Authentication and all starts remain locked.`, result.status !== "AUTH_UNCONFIGURED");
  } catch (error) {
    say(error.message, true);
  } finally {
    button.disabled = false;
  }
}

async function armActualWSLEgressHarness() {
  try {
    actualWSLHarnessArm = await api("/api/isolation/wsl/egress-harness/actual/arm", { method: "POST" });
    renderActualWSLEgressHarness(await api("/api/isolation/wsl/egress-harness/actual"));
    say("A two-minute, one-time WSL harness window is armed locally. The next actual harness request consumes both capabilities.");
  } catch (error) {
    actualWSLHarnessArm = null;
    say(error.message, true);
  }
}

async function runActualWSLEgressHarness() {
  if (!actualWSLHarnessArm) return;
  try {
    const result = await api("/api/isolation/wsl/egress-harness/actual", {
      method: "POST",
      body: JSON.stringify({
        window_nonce: actualWSLHarnessArm.window_nonce,
        arm_nonce: actualWSLHarnessArm.arm_nonce,
      }),
    });
    actualWSLHarnessArm = null;
    renderActualWSLEgressHarness(result);
  } catch (error) {
    // The server consumes a valid pair before execution validation, so never
    // keep a browser-side capability after any attempted actual request.
    actualWSLHarnessArm = null;
    say(error.message, true);
    renderActualWSLEgressHarness(await api("/api/isolation/wsl/egress-harness/actual"));
  }
}

async function issueCodexProcessCanaryPermit() {
  try {
    codexProcessCanaryPermit = await api("/api/isolation/wsl/codex-process-canary/permit", { method: "POST" });
    codexProcessCanaryArm = null;
    renderCodexProcessCanary(await api("/api/isolation/wsl/codex-process-canary"));
    say("A local two-minute Offline Canary Permit is armed. It authorizes one canary-window request only; external model tokens remain 0.");
  } catch (error) {
    codexProcessCanaryPermit = null;
    codexProcessCanaryArm = null;
    say(error.message, true);
  }
}

async function armCodexProcessCanary() {
  if (!codexProcessCanaryPermit) return;
  try {
    codexProcessCanaryArm = await api("/api/isolation/wsl/codex-process-canary/arm", {
      method: "POST",
      body: JSON.stringify({ permit_nonce: codexProcessCanaryPermit.permit_nonce }),
    });
    renderCodexProcessCanary(await api("/api/isolation/wsl/codex-process-canary"));
    say("A one-time offline Codex canary window is armed locally. Runtime and live execution remain locked.");
  } catch (error) {
    codexProcessCanaryArm = null;
    codexProcessCanaryPermit = null;
    say(error.message, true);
  }
}

async function runCodexProcessCanary() {
  if (!codexProcessCanaryPermit || !codexProcessCanaryArm) return;
  const button = $("run-codex-process-canary");
  try {
    // Disable synchronously before the request so the browser cannot resend
    // the same two one-time capabilities while the response is pending.
    if (button) button.disabled = true;
    // This is the only UI path that can request the sealed actual runner.
    // It always clears both browser-side capabilities after one submission.
    const result = await api("/api/isolation/wsl/codex-process-canary/one-shot", {
      method: "POST",
      body: JSON.stringify({
        permit_nonce: codexProcessCanaryPermit.permit_nonce,
        canary_nonce: codexProcessCanaryArm.canary_nonce,
      }),
    });
    codexProcessCanaryPermit = null;
    codexProcessCanaryArm = null;
    renderCodexProcessCanary(result);
  } catch (error) {
    codexProcessCanaryPermit = null;
    codexProcessCanaryArm = null;
    say(error.message, true);
    renderCodexProcessCanary(await api("/api/isolation/wsl/codex-process-canary"));
  }
}

async function runSealedEgressHarness() {
  const button = $("run-wsl-egress-harness");
  try {
    button.disabled = true;
    say("Running the deterministic in-memory harness only; the Phase 3 WSL runner is not selected, so no WSL, socket, network, Codex, or model process starts...");
    const result = await api("/api/isolation/wsl/egress-harness", { method: "POST" });
    renderSealedEgressHarness(result);
    say(`Sealed egress fake harness: ${result.status}. Authentication and every live start remain locked.`, result.status !== "PASSED");
  } catch (error) {
    say(error.message, true);
  } finally {
    if (wslHarnessStatus === "READY") button.disabled = false;
  }
}

function updateExecuteState() {
  $("execute").disabled = !planIsExecutable();
}

function resetCapsule() {
  currentCapsule = null;
  $("capsule-status").textContent = "NOT CREATED";
  $("capsule-files").textContent = "0";
  $("capsule-size").textContent = "0 bytes";
  $("capsule-ranges").textContent = "None";
  $("capsule-reasons").textContent = "";
  $("create-capsule").disabled = !currentPlan;
}

function renderCapsule(capsule) {
  currentCapsule = capsule;
  $("capsule-status").textContent = capsule.status || "UNKNOWN";
  $("capsule-files").textContent = String(capsule.file_count || 0);
  $("capsule-size").textContent = `${Number(capsule.total_bytes || 0).toLocaleString()} bytes`;
  const ranges = capsule.ranges || [];
  $("capsule-ranges").textContent = ranges.length
    ? ranges.map((entry) => `${entry.path}:${entry.start_line}-${entry.end_line}`).join(", ")
    : "None";
  $("capsule-reasons").textContent = (capsule.hold_reasons || []).join("\n");
  $("create-capsule").disabled = !currentPlan;
}

function invalidateRoutePlan() {
  currentPlan = null;
  $("route-plan").classList.add("hidden");
  $("planned-budget").value = "Route Plan 생성 후 표시";
  resetCapsule();
  updateExecuteState();
}

function renderRoutePlan(plan) {
  currentPlan = plan;
  $("route-plan").classList.remove("hidden");
  $("plan-status").textContent = plan.status;
  $("plan-id").textContent = plan.plan_id;
  $("plan-hash").textContent = plan.decision_hash;
  $("plan-expiry").textContent = new Date(plan.expires_at).toLocaleString();
  $("plan-final").textContent = plan.final ? `${plan.final.model} / ${plan.final.effort}` : "HOLD";
  $("plan-budget").textContent = plan.budget
    ? `${plan.budget_level} · ${Number(plan.budget.tokens).toLocaleString()} tokens / ${plan.budget.tools} tools / ${plan.budget.changed_files} files`
    : "—";
  $("planned-budget").value = plan.budget
    ? `${plan.budget_level} · ${Number(plan.budget.tokens).toLocaleString()} tokens`
    : "HOLD";
  $("plan-scope").textContent = `${plan.planned_file_count} exact files`;
  const evidence = plan.validation_evidence || {};
  $("plan-validation").textContent =
    `commands=${Boolean(evidence.validation_commands_present)}, local_target=${Boolean(evidence.local_test_target_exists)}`;
  $("plan-reasons").textContent = (plan.hold_reasons || []).join("\n");
  resetCapsule();
  updateExecuteState();
  if (planExpiryTimer) clearTimeout(planExpiryTimer);
  const delay = Math.max(0, Date.parse(plan.expires_at) - Date.now());
  planExpiryTimer = setTimeout(() => {
    updateExecuteState();
    say("Route Plan expired. Create a new plan before execution.", true);
  }, Math.min(delay + 50, 2_147_483_647));
}

async function createCapsule() {
  try {
    if (!currentPlan) {
      throw new Error("Create a Route Plan before creating an Evidence Capsule.");
    }
    say("Creating bounded Evidence Capsule...");
    const capsule = await api(`/api/route-plans/${encodeURIComponent(currentPlan.plan_id)}/capsule`, { method: "POST" });
    renderCapsule(capsule);
    say(
      capsule.status === "READY" ? "Evidence Capsule created without starting Codex." : "Evidence Capsule is HOLD or INVALID.",
      capsule.status !== "READY",
    );
  } catch (error) {
    say(error.message, true);
  }
}

async function createRoutePlan() {
  try {
    const decision = JSON.parse($("decision").value);
    const payload = {
      project_name: $("project-name").value,
      project_id: projectIdFromName($("project-name").value),
      root: $("root").value,
      task: $("task").value,
      decision,
      permission: $("permission").value,
      explicit_ultra_approval: $("router-ultra-approval").checked,
    };
    say("Creating immutable Route Plan...");
    const plan = await api("/api/route-plans", { method: "POST", body: JSON.stringify(payload) });
    renderRoutePlan(plan);
    renderRoutePreview(plan.route_preview);
    say(
      plan.status === "PREVIEW" ? "Route Plan created. Live execution remains locked in this release." : "Route Plan is HOLD.",
      plan.status !== "PREVIEW",
    );
  } catch (error) {
    invalidateRoutePlan();
    say(error.message.includes("JSON") ? "The decision JSON is invalid." : error.message, true);
  }
}

async function makePreflight() {
  try {
    const payload = {
      project_name: $("project-name").value,
      root: $("root").value,
      task: $("task").value,
    };
    const data = await api("/api/preflight", { method: "POST", body: JSON.stringify(payload) });
    $("risk").textContent = data.risk;
    $("file-count").textContent = data.candidate_files;
    $("context").textContent = `${data.estimated_context.toLocaleString()} tokens`;
    $("git-status").textContent = `Git: ${data.git_status}`;
    $("web-packet").value = data.web_packet;
    say("Preflight packet generated.");
  } catch (error) {
    say(error.message, true);
  }
}

async function copyPacket() {
  try {
    await navigator.clipboard.writeText($("web-packet").value);
    say("Preflight packet copied to clipboard.");
  } catch {
    say("Clipboard copy is unavailable in this browser.", true);
  }
}

function fieldRow(labelText, valueText) {
  const wrapper = document.createElement("div");
  const label = document.createElement("dt");
  const value = document.createElement("dd");
  label.textContent = labelText;
  value.textContent = valueText || "—";
  wrapper.append(label, value);
  return wrapper;
}

function renderApprovalCard(approval) {
  const card = document.createElement("article");
  card.className = "approval-card";

  const title = document.createElement("h3");
  title.textContent = `Approval request · ${approval.kind}`;

  const dl = document.createElement("dl");
  const pairs = [
    ["Command", approval.command || "—"],
    ["CWD", approval.cwd || "—"],
    ["Files", (approval.paths || []).join(", ") || "—"],
    ["Reason", approval.reason || "—"],
    ["Permissions", approval.permissions ? JSON.stringify(approval.permissions, null, 2) : "—"],
  ];
  for (const [labelText, valueText] of pairs) {
    const label = document.createElement("dt");
    const value = document.createElement("dd");
    label.textContent = labelText;
    value.textContent = valueText;
    dl.append(label, value);
  }

  const actions = document.createElement("div");
  actions.className = "approval-actions";
  const labels = {
    accept: "Allow once",
    acceptForSession: "Allow session",
    decline: "Decline",
    cancel: "Cancel",
  };
  const decisions = ["accept", "acceptForSession", "decline", "cancel"].filter((decision) =>
    (approval.available_decisions || []).includes(decision),
  );
  for (const decision of decisions) {
    const button = document.createElement("button");
    button.className = `button ${decision === "cancel" ? "cancel" : decision === "decline" ? "decline" : ""}`;
    button.type = "button";
    button.dataset.approval = String(approval.request_id);
    button.dataset.decision = decision;
    button.textContent = labels[decision];
    button.onclick = () => answerApproval(button.dataset.approval, button.dataset.decision);
    actions.appendChild(button);
  }

  card.append(title, dl, actions);
  return card;
}

function renderApprovals(approvals) {
  const root = $("approvals");
  root.replaceChildren();
  root.classList.toggle("hidden", !approvals.length);
  for (const approval of approvals) {
    root.appendChild(renderApprovalCard(approval));
  }
}

function renderRun(run) {
  currentRun = run;
  $("run-panel").classList.remove("hidden");
  $("run-status").textContent = run.status;
  $("run-tokens").textContent = `${run.tokens.toLocaleString()} / ${run.budget.tokens.toLocaleString()}`;
  $("run-tools").textContent = `${run.tool_calls} / ${run.budget.tools}`;
  $("run-files").textContent = `${run.changed_files.length} / ${run.budget.changed_files}`;
  $("run-failures").textContent = `${run.failed_commands} cmd / ${run.failed_tests} test`;
  $("run-model").textContent = `${run.model} / ${run.effort}`;
  $("events").textContent = run.events.join("\n") || "Waiting for events...";
  $("interrupt").disabled = !["running", "starting", "interrupting"].includes(run.status);
  renderApprovals(run.approvals || []);
  refreshTokenLedger().catch(() => {});
}

async function answerApproval(requestId, decision) {
  if (!currentRun) return;
  try {
    await api(`/api/runs/${currentRun.id}/approvals/${encodeURIComponent(requestId)}`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    });
    say(`Approval reply sent: ${decision}`);
  } catch (error) {
    say(error.message, true);
  }
}

function watch(runId) {
  if (stream) stream.close();
  stream = new EventSource(`/api/events/${runId}`);
  stream.addEventListener("run", (event) => renderRun(JSON.parse(event.data)));
  stream.onerror = () => {
    if (currentRun && !["completed", "failed", "interrupted"].includes(currentRun.status)) {
      say("Connection to the event stream was interrupted.", true);
    }
  };
}

async function execute() {
  try {
    if (!planIsExecutable()) {
      throw new Error("Live execution remains locked in this release.");
    }
    const payload = {
      route_plan_id: currentPlan.plan_id,
    };
    say("Creating Codex run...");
    const run = await api("/api/run", { method: "POST", body: JSON.stringify(payload) });
    renderRun(run);
    watch(run.id);
    currentPlan.used = true;
    updateExecuteState();
    say("Run started.");
  } catch (error) {
    say(error.message.includes("JSON") ? "The decision JSON is invalid." : error.message, true);
  }
}

async function interrupt() {
  if (!currentRun) return;
  try {
    renderRun(await api(`/api/runs/${currentRun.id}/interrupt`, { method: "POST" }));
  } catch (error) {
    say(error.message, true);
  }
}

async function startBridge() {
  try {
    const bridge = await api("/api/bridge/tasks", {
      method: "POST",
      body: JSON.stringify({
        project_name: $("project-name").value,
        project_id: projectIdFromName($("project-name").value),
        root: $("root").value,
        task: $("task").value,
        permission: $("permission").value,
        chat_url: $("bridge-chat-url").value || null,
      }),
    });
    bridgeManualMode = null;
    renderBridge(bridge);
    say("Bridge task created. Copy the architecture packet.");
  } catch (error) {
    say(error.message, true);
  }
}

async function copyBridgePacket() {
  const packet = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/packet`);
  $("bridge-packet").value = packet.packet;
  $("bridge-packet-details").classList.remove("hidden");
  try {
    await navigator.clipboard.writeText(packet.packet);
    const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/copied`, { method: "POST" });
    bridgeManualMode = null;
    renderBridge(bridge);
    if (bridge.chat_url) {
      const tab = window.open(bridge.chat_url, "_blank", "noopener");
      if (tab) tab.opener = null;
    }
    say("Packet copied. The configured Web GPT URL was opened in a new tab.");
  } catch {
    bridgeManualMode = "mark-copied";
    renderBridge(currentBridge);
    say("Clipboard copy failed. Copy the collapsed packet manually, then confirm.", true);
  }
}

async function importBridgeResponse() {
  let packet;
  if (bridgeManualMode === "import") {
    packet = $("bridge-manual-response").value;
  } else {
    try {
      packet = await navigator.clipboard.readText();
    } catch {
      bridgeManualMode = "import";
      renderBridge(currentBridge);
      say("Clipboard read failed. Paste the response packet into the manual field.", true);
      return;
    }
  }
  const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/import`, {
    method: "POST", body: JSON.stringify({ packet }),
  });
  $("bridge-manual-response").value = "";
  bridgeManualMode = null;
  renderBridge(bridge);
  say("Web GPT response validated and recorded.");
}

async function prepareBridgeReview() {
  const result = JSON.parse($("bridge-result").value);
  const validation = JSON.parse($("bridge-validation").value);
  const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/review`, {
    method: "POST", body: JSON.stringify({ result, validation }),
  });
  renderBridge(bridge);
  say("Review packet is ready to copy.");
}

async function bridgeAction() {
  try {
    if (bridgeManualMode === "mark-copied") {
      const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/copied`, { method: "POST" });
      bridgeManualMode = null;
      renderBridge(bridge);
      return;
    }
    switch (currentBridge.active_action) {
      case "copy_architect_request":
      case "copy_review_request":
        await copyBridgePacket();
        break;
      case "import_architect_response":
      case "import_review_response":
        await importBridgeResponse();
        break;
      case "prepare_review_request":
        await prepareBridgeReview();
        break;
      case "restart":
        bridgeManualMode = null;
        renderBridge(await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/restart`, { method: "POST" }));
        break;
      default:
        throw new Error("Bridge action is unavailable.");
    }
  } catch (error) {
    say(error.message.includes("JSON") ? "Bridge result and validation must be valid JSON." : error.message, true);
  }
}

function bridgePresentation(bridge) {
  const actions = {
    copy_architect_request: ["Local -> Web GPT", "ARCHITECT_REQUEST", "Copy the architecture packet.", "Import the response.", "send"],
    import_architect_response: ["Web GPT -> Local", "ARCHITECT_RESPONSE", "Import the architecture response.", "The app validates it locally.", "receive"],
    prepare_review_request: ["Local -> Local", "REVIEW_REQUEST", "Enter actual result and validation.", "Copy the review packet.", "auto"],
    processing_response: ["Web GPT -> Local", bridge?.packet_type || "-", "The pasted response is being validated locally.", "Wait for the updated snapshot.", "auto"],
    prepare_evidence: ["Local -> Local", "EVIDENCE_REQUIRED", "Map each request to an exact project-relative file and collect it.", "A new ARCHITECT_REQUEST is enabled when required evidence is ready.", "auto"],
    copy_review_request: ["Local -> Web GPT", "REVIEW_REQUEST", "Copy the review packet.", "Import the review response.", "send"],
    import_review_response: ["Web GPT -> Local", "REVIEW_RESPONSE", "Import the review response.", "The app records the verdict.", "receive"],
    restart: ["Local -> Web GPT", "ARCHITECT_REQUEST", "Start a new architecture cycle.", "A fresh nonce and Route Plan are required.", bridge.status === "SUCCESS" ? "done" : "hold"],
    restart_required: ["Local", "v1", "This v1 task cannot be converted.", "Start a new v2 Bridge task.", "hold"],
  };
  return actions[bridge?.active_action] || ["Local", "-", "No action is available.", "Start a new Bridge task.", "idle"];
}

function renderBridgeEvidence(bridge) {
  const panel = $("bridge-evidence");
  panel.replaceChildren();
  const requests = bridge?.evidence_requests || [];
  panel.classList.toggle("hidden", bridge?.active_action !== "prepare_evidence");
  for (const request of requests) {
    const card = document.createElement("article");
    card.className = "evidence-card";
    const title = document.createElement("strong");
    title.textContent = `${request.label} (${request.type}) — ${request.state}`;
    const why = document.createElement("p");
    why.textContent = request.reason;
    const input = document.createElement("input");
    input.type = "text"; input.placeholder = "Project-relative file path"; input.value = request.mapped_path || "";
    const map = document.createElement("button");
    map.type = "button"; map.className = "button ghost"; map.textContent = "Map local file";
    const collect = document.createElement("button");
    collect.type = "button"; collect.className = "button"; collect.textContent = "Collect safe summary";
    map.onclick = async () => {
      try { renderBridge(await api(`/api/bridge/tasks/${encodeURIComponent(bridge.task_id)}/evidence/${encodeURIComponent(request.request_id)}/map`, {method:"POST", body: JSON.stringify({path: input.value})})); } catch (error) { say(error.message, true); }
    };
    collect.disabled = request.state !== "MAPPED" && request.state !== "FAILED";
    collect.onclick = async () => {
      try { renderBridge(await api(`/api/bridge/tasks/${encodeURIComponent(bridge.task_id)}/evidence/${encodeURIComponent(request.request_id)}/collect`, {method:"POST"})); } catch (error) { say(error.message, true); }
    };
    const status = document.createElement("small");
    status.textContent = request.error_reason || (request.required ? "Required evidence" : "Optional evidence");
    card.append(title, why, input, map, collect, status); panel.appendChild(card);
  }
}

function renderBridge(bridge) {
  currentBridge = bridge;
  const start = $("bridge-start");
  const action = $("bridge-action");
  if (!bridge) {
    $("bridge-status").textContent = "NOT STARTED";
    $("bridge-status").className = "status bridge-flag idle";
    $("bridge-phase").textContent = "-";
    $("bridge-source").textContent = "Local";
    $("bridge-destination").textContent = "Web GPT";
    $("bridge-type").textContent = "-";
    $("bridge-now").textContent = "Start a Bridge task.";
    $("bridge-next").textContent = "Copy the architecture packet.";
    $("bridge-message").textContent = "No Bridge task is active.";
    start.disabled = false; start.classList.remove("hidden"); action.disabled = true; action.classList.add("hidden");
    $("bridge-review-fields").classList.add("hidden");
    $("bridge-evidence").classList.add("hidden");
    return;
  }
  const [direction, type, now, next, color] = bridgePresentation(bridge);
  const [source, destination] = direction.split(" -> ");
  $("bridge-status").textContent = bridge.status;
  $("bridge-status").className = `status bridge-flag ${color}`;
  $("bridge-phase").textContent = bridge.phase || "-";
  $("bridge-source").textContent = source || "Local";
  $("bridge-destination").textContent = destination || "Local";
  $("bridge-type").textContent = type;
  $("bridge-now").textContent = now;
  $("bridge-next").textContent = next;
  $("bridge-message").textContent = bridge.restart_required
    ? "Protocol v1 is restart-required and was not converted."
    : bridge.active_action === "processing_response"
      ? "The pasted response is being validated locally."
      : bridge.hold_reason || (bridge.requested_evidence?.length ? `Requested evidence: ${bridge.requested_evidence.map((item) => item.label || item).join("; ")}` : "Only the displayed action is enabled.");
  start.disabled = true; start.classList.add("hidden"); action.classList.remove("hidden");
  action.disabled = ["prepare_evidence", "restart_required", "processing_response"].includes(bridge.active_action);
  const labels = {copy_architect_request:"Copy architecture packet", import_architect_response: bridgeManualMode === "import" ? "Import pasted architecture response" : "Read and import architecture response", prepare_review_request:"Create review packet from local result", processing_response:"Processing response", prepare_evidence:"Prepare required evidence below", copy_review_request:"Copy review packet", import_review_response: bridgeManualMode === "import" ? "Import pasted review response" : "Read and import review response", restart:"Start a new architecture cycle", restart_required:"Start a new v2 Bridge task"};
  action.textContent = bridgeManualMode === "mark-copied" ? "Mark packet copied manually" : labels[bridge.active_action] || "Unavailable";
  $("bridge-review-fields").classList.toggle("hidden", bridge.active_action !== "prepare_review_request");
  $("bridge-manual-response").classList.toggle("hidden", bridgeManualMode !== "import");
  $("bridge-packet-details").classList.toggle("hidden", bridge.active_action === "processing_response");
  renderBridgeEvidence(bridge);
}

async function showBridgePacket(taskId) {
  try {
    const data = await api(`/api/bridge/tasks/${encodeURIComponent(taskId)}/packet`);
    $("bridge-packet").value = data.packet;
    $("bridge-packet-details").classList.remove("hidden");
  } catch { /* terminal and evidence-required states have no packet preview */ }
}

async function restoreBridge() {
  try {
    const data = await api("/api/bridge/tasks/recent");
    const tasks = data.tasks || [];
    $("bridge-recent").textContent = tasks.length ? `Recovered ${tasks.length} active Bridge task(s); latest is shown.` : "No unfinished Bridge task to recover.";
    if (data.latest) { bridgeManualMode = null; renderBridge(data.latest); await showBridgePacket(data.latest.task_id); }
  } catch { $("bridge-recent").textContent = "Bridge recovery is unavailable."; }
}

function renderCatalogEntries(entries) {
  const body = $("catalog-entries");
  body.replaceChildren();
  for (const entry of entries) {
    const row = document.createElement("tr");
    const selectCell = document.createElement("td");
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "catalog-select";
    checkbox.checked = selectedCatalogEntries.has(entry.entry_id);
    checkbox.onchange = () => {
      if (checkbox.checked) selectedCatalogEntries.add(entry.entry_id);
      else selectedCatalogEntries.delete(entry.entry_id);
      updateCatalogProbeButton();
    };
    selectCell.appendChild(checkbox);
    row.appendChild(selectCell);
    for (const value of [currentCatalogSource?.alias || "-", entry.relative_path, entry.asset_kind, String(entry.size), entry.status, entry.entry_id]) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.appendChild(cell);
    }
    body.appendChild(row);
  }
  updateCatalogProbeButton();
}

async function refreshCatalogEntries() {
  if (!currentCatalogSource) return;
  const query = new URLSearchParams();
  const fields = [["status", "catalog-filter-status"], ["asset_kind", "catalog-filter-kind"], ["extension", "catalog-filter-extension"]];
  for (const [name, id] of fields) { if ($(id).value.trim()) query.set(name, $(id).value.trim()); }
  const suffix = query.toString() ? `?${query}` : "";
  const data = await api(`/api/catalog/sources/${encodeURIComponent(currentCatalogSource.source_id)}/entries${suffix}`);
  renderCatalogEntries(data.entries || []);
}

function renderCatalogScan(scan) {
  const metrics = scan.metrics || {};
  $("catalog-scan-status").textContent = scan.status;
  $("catalog-progress").textContent = `${currentCatalogSource?.alias || "Source"}: ${metrics.files_seen || 0} files, ${metrics.bytes_indexed || 0} indexed bytes, ${metrics.content_bytes_read || 0} content bytes read; added ${metrics.added || 0}, modified ${metrics.modified || 0}, missing ${metrics.missing || 0}, rejected ${metrics.rejected || 0}.`;
  $("catalog-scan").disabled = false;
  $("catalog-resume").disabled = scan.status !== "INTERRUPTED";
  $("catalog-cancel").disabled = true;
}

function updateCatalogProbeButton() {
  const count = selectedCatalogEntries.size;
  $("catalog-probe").disabled = !currentCatalogSource || count === 0 || count > 50;
  $("catalog-probe-summary").textContent = count
    ? `${count} catalog entr${count === 1 ? "y" : "ies"} selected. Probe reads limited header/sample bytes only and never returns an absolute path.`
    : "Select up to 50 catalog entries. Phase 2 samples only limited file regions and never parses the whole file.";
}

function renderFormatProbeResults(results) {
  const body = $("format-probe-results");
  body.replaceChildren();
  for (const result of results) {
    const row = document.createElement("tr");
    appendCell(row, result.alias || currentCatalogSource?.alias || "-");
    appendCell(row, result.relative_path || "-");
    appendCell(row, result.detected_format || "UNKNOWN");
    appendCell(row, result.detected_confidence || "-");
    const extensionCell = appendCell(row, result.extension_match || "UNKNOWN");
    extensionCell.className = result.extension_match === "MISMATCH" ? "probe-mismatch" : result.extension_match === "MATCH" ? "probe-match" : "";
    appendCell(row, result.next_inspector || "NONE");
    appendCell(row, String(result.bytes_read || 0));
    appendCell(row, result.status || "UNKNOWN");
    body.appendChild(row);
  }
}

async function registerCatalogSource() {
  try {
    const source = await api("/api/catalog/sources", { method: "POST", body: JSON.stringify({alias: $("catalog-alias").value, root: $("catalog-root").value}) });
    currentCatalogSource = source;
    selectedCatalogEntries = new Set();
    $("catalog-scan").disabled = false;
    $("catalog-resume").disabled = true;
    $("catalog-progress").textContent = `${source.alias} is registered. Its local path remains private.`;
    renderCatalogEntries([]);
    renderFormatProbeResults([]);
  } catch (error) { say(error.message, true); }
}

async function scanCatalog(resume = false) {
  if (!currentCatalogSource) return;
  try {
    $("catalog-scan").disabled = true;
    $("catalog-resume").disabled = true;
    $("catalog-cancel").disabled = false;
    $("catalog-scan-status").textContent = "SCANNING";
    const action = resume ? "resume" : "scan";
    const scan = await api(`/api/catalog/sources/${encodeURIComponent(currentCatalogSource.source_id)}/${action}`, {method: "POST", body: JSON.stringify({})});
    renderCatalogScan(scan);
    await refreshCatalogEntries();
  } catch (error) { $("catalog-scan-status").textContent = "FAILED"; $("catalog-scan").disabled = false; say(error.message, true); }
}

async function cancelCatalog() {
  if (!currentCatalogSource) return;
  try {
    await api(`/api/catalog/sources/${encodeURIComponent(currentCatalogSource.source_id)}/cancel`, {method: "POST"});
    $("catalog-progress").textContent = "Cancellation requested; the current metadata batch will finish safely.";
  } catch (error) { say(error.message, true); }
}

async function runFormatProbe() {
  if (!currentCatalogSource || !selectedCatalogEntries.size) return;
  try {
    $("catalog-probe").disabled = true;
    const data = await api("/api/format-probes", {
      method: "POST",
      body: JSON.stringify({catalog_entry_ids: Array.from(selectedCatalogEntries).slice(0, 50)}),
    });
    renderFormatProbeResults(data.results || []);
    say(`Format probe completed for ${(data.results || []).length} catalog entr${(data.results || []).length === 1 ? "y" : "ies"}.`);
  } catch (error) {
    say(error.message, true);
  } finally {
    updateCatalogProbeButton();
  }
}

function formatLedgerCount(value) {
  if (typeof value !== "number" || Number.isNaN(value)) return "?";
  return value.toLocaleString();
}

function formatLedgerValue(record) {
  if (!record) return "?";
  const processed = typeof record.processed_tokens === "number" ? record.processed_tokens.toLocaleString() : "?";
  const quality = record.quality || "UNKNOWN";
  return `${processed} (${quality})`;
}

function renderTokenLedger(report) {
  const summary = report?.summary || {};
  const usage = report?.usage_totals || {};
  $("ledger-summary-status").textContent = summary.comparison_count ? "ACTIVE" : "NO DATA";
  $("ledger-summary-message").textContent = summary.message || "?? ?? ?? ???";
  $("ledger-baseline-processed").textContent = formatLedgerCount(report?.baselines?.[0]?.processed_tokens);
  $("ledger-actual-processed").textContent = formatLedgerCount(report?.runs?.[0]?.processed_tokens);
  $("ledger-processed-savings").textContent = summary.comparable_count ? String(report?.comparisons?.[0]?.processed_savings ?? "?") : "?";
  $("ledger-model-turns").textContent = formatLedgerCount(report?.runs?.reduce((total, run) => total + (Number.isFinite(run.model_turns) ? run.model_turns : 0), 0));
  $("ledger-retries").textContent = formatLedgerCount(report?.runs?.reduce((total, run) => total + (Number.isFinite(run.retries) ? run.retries : 0), 0));
  $("ledger-report").textContent = JSON.stringify(report || {}, null, 2);
  const body = $("ledger-comparisons");
  body.replaceChildren();
  for (const comparison of report?.comparisons || []) {
    const row = document.createElement("tr");
    appendCell(row, comparison.comparison_key || "?");
    appendCell(row, comparison.status || "NOT_COMPARABLE");
    const baseline = document.createElement("td");
    baseline.textContent = formatLedgerValue(comparison.baseline);
    baseline.className = `ledger-quality ${(comparison.baseline?.quality || "").toLowerCase()}`;
    row.appendChild(baseline);
    const actual = document.createElement("td");
    actual.textContent = formatLedgerValue(comparison.actual);
    actual.className = `ledger-quality ${(comparison.actual?.quality || "").toLowerCase()}`;
    row.appendChild(actual);
    appendCell(row, comparison.processed_savings == null ? "?" : String(comparison.processed_savings));
    appendCell(row, `${comparison.baseline?.model_turns ?? "?"} / ${comparison.actual?.model_turns ?? "?"}`);
    appendCell(row, `${comparison.baseline?.retries ?? "?"} / ${comparison.actual?.retries ?? "?"}`);
    body.appendChild(row);
  }
  if (usage.web_packet_bytes || usage.evidence_bytes || usage.catalog_source_bytes || usage.probe_bytes) {
    $("ledger-summary-message").textContent = `${summary.message || "?? ?? ?? ???"} Bridge=${usage.web_packet_bytes || 0} Evidence=${usage.evidence_bytes || 0} Catalog=${usage.catalog_source_bytes || 0} Probe=${usage.probe_bytes || 0}`;
  }
}

async function refreshTokenLedger() {
  try {
    const report = await api("/api/token-ledger/report");
    renderTokenLedger(report);
  } catch (error) {
    $("ledger-summary-status").textContent = "ERROR";
    $("ledger-summary-message").textContent = error.message;
  }
}

async function importTokenLedgerBaseline() {
  try {
    const report = await api("/api/token-ledger/baselines", {
      method: "POST",
      body: $("ledger-baseline-input").value,
    });
    renderTokenLedger(report.token_ledger || report);
    say("Token ledger baseline imported.");
  } catch (error) {
    say(error.message, true);
  }
}

async function exportTokenLedger(format) {
  try {
    const response = await fetch(`/api/token-ledger/export?format=${encodeURIComponent(format)}`, {
      headers: { "Content-Type": "application/json" },
    });
    const text = await response.text();
    if (!response.ok) throw new Error(text || "Export failed");
    const mime = format === "markdown" ? "text/markdown" : "application/json";
    const blob = new Blob([text], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `TOKEN_SAVINGS_REPORT.${format === "markdown" ? "md" : "json"}`;
    anchor.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    say(error.message, true);
  }
}
$("ledger-refresh").onclick = refreshTokenLedger;
$("ledger-import").onclick = importTokenLedgerBaseline;
$("ledger-export-json").onclick = () => exportTokenLedger("json");
$("ledger-export-md").onclick = () => exportTokenLedger("markdown");
$("save-wsl-isolation-config").onclick = saveWSLIsolationConfig;
$("run-wsl-isolation-probe").onclick = runWSLIsolationProbe;
$("run-wsl-isolation-repro").onclick = runWSLIsolationRepro;
$("save-wsl-runtime-config").onclick = saveWSLCodexRuntimeConfig;
$("run-wsl-runtime-preflight").onclick = runWSLCodexRuntimePreflight;
$("create-wsl-egress-contract").onclick = createSealedEgressContract;
$("run-wsl-egress-harness").onclick = runSealedEgressHarness;
$("arm-actual-wsl-egress-harness").onclick = armActualWSLEgressHarness;
$("run-actual-wsl-egress-harness").onclick = runActualWSLEgressHarness;
$("issue-codex-process-canary-permit").onclick = issueCodexProcessCanaryPermit;
$("arm-codex-process-canary").onclick = armCodexProcessCanary;
$("run-codex-process-canary").onclick = runCodexProcessCanary;
for (const id of ["catalog-filter-status", "catalog-filter-kind", "catalog-filter-extension"]) $(id).addEventListener("change", () => refreshCatalogEntries().catch((error) => say(error.message, true)));
renderBridge(null);
restoreBridge();
updateCatalogProbeButton();
for (const id of ["project-name", "root", "task", "decision", "permission"]) {
  $(id).addEventListener("input", invalidateRoutePlan);
  $(id).addEventListener("change", invalidateRoutePlan);
}
