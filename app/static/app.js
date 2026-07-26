const $ = (id) => document.getElementById(id);

let catalog = [];
let currentRun = null;
let currentPlan = null;
let stream = null;
let planExpiryTimer = null;

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
  if (!currentPlan || currentPlan.status !== "PREVIEW" || currentPlan.used) return false;
  const expires = Date.parse(currentPlan.expires_at);
  return Number.isFinite(expires) && expires > Date.now() && currentPlan.permission === "read-only";
}

function updateExecuteState() {
  $("execute").disabled = !planIsExecutable();
}

function invalidateRoutePlan() {
  currentPlan = null;
  $("route-plan").classList.add("hidden");
  $("planned-budget").value = "Route Plan 생성 후 표시";
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
  updateExecuteState();
  if (planExpiryTimer) clearTimeout(planExpiryTimer);
  const delay = Math.max(0, Date.parse(plan.expires_at) - Date.now());
  planExpiryTimer = setTimeout(() => {
    updateExecuteState();
    say("Route Plan expired. Create a new plan before execution.", true);
  }, Math.min(delay + 50, 2_147_483_647));
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
      plan.status === "PREVIEW" ? "Route Plan created. Read Only execution is ready." : "Route Plan is HOLD.",
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
      throw new Error("A current PREVIEW Route Plan is required.");
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

$("connect").onclick = connect;
$("preflight").onclick = makePreflight;
$("copy-packet").onclick = copyPacket;
$("router-preview").onclick = previewRouter;
$("create-plan").onclick = createRoutePlan;
$("execute").onclick = execute;
$("interrupt").onclick = interrupt;
for (const id of ["project-name", "root", "task", "decision", "permission"]) {
  $(id).addEventListener("input", invalidateRoutePlan);
  $(id).addEventListener("change", invalidateRoutePlan);
}
