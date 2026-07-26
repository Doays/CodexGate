const $ = (id) => document.getElementById(id);

let catalog = [];
let currentRun = null;
let stream = null;

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
  model.disabled = false;
  model.onchange = loadEfforts;
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
  effort.disabled = false;
}

async function connect() {
  try {
    say("Connecting to Codex app-server...");
    const data = await api("/api/connect", { method: "POST" });
    loadModels(data.choices);
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
    $("execute").disabled = false;
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
    const decision = JSON.parse($("decision").value);
    const payload = {
      project_name: $("project-name").value,
      project_id: projectIdFromName($("project-name").value),
      root: $("root").value,
      task: $("task").value,
      decision,
      model: $("model").value,
      effort: $("effort").value,
      permission: $("permission").value,
      budget_level: $("budget").value,
    };
    say("Creating Codex run...");
    const run = await api("/api/run", { method: "POST", body: JSON.stringify(payload) });
    renderRun(run);
    watch(run.id);
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
$("execute").onclick = execute;
$("interrupt").onclick = interrupt;
