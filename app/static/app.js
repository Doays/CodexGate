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
let stream = null;
let planExpiryTimer = null;
let currentBridge = null;
let bridgeManualMode = null;
let currentCatalogSource = null;
let selectedCatalogEntries = new Set();

const STATUS_LABELS = {
  UNKNOWN: "확인 전",
  UNCONFIGURED: "미설정",
  DISABLED: "비활성",
  READY: "준비됨",
  PASSED: "통과",
  HOLD: "보류",
  ERROR: "오류",
  BLOCKED: "차단됨",
  "FAKE BLOCKED": "가짜 실행 차단",
  "WSL NOT RUN": "WSL 미실행",
  SAFE_CANDIDATE: "안전 후보",
  SAFE_REPRODUCIBLE: "안전 재현 가능",
  EGRESS_UNCONFIGURED: "외부 통신 미설정",
  AUTH_UNCONFIGURED: "인증 미설정",
  AVAILABLE: "사용 가능",
  LIMITED: "제한됨",
  DEPLETED: "소진됨",
  ARMED: "대기 장착",
  CONSUMED: "소비됨",
  PREVIEW: "미리보기",
  NOT_COMPARABLE: "비교 불가",
  MAPPED: "매핑됨",
  NOT_CREATED: "생성 전",
  "NO DATA": "데이터 없음",
  ACTIVE: "활성",
  IDLE: "대기",
  SCANNING: "스캔 중",
  FAILED: "실패",
  INTERRUPTED: "중단됨",
  "NOT STARTED": "시작 전",
  starting: "시작 중",
  running: "실행 중",
  completed: "완료",
  failed: "실패",
  interrupted: "중단됨",
  interrupting: "중단 중",
};

function statusLabel(value) {
  return STATUS_LABELS[value] || value || "확인 전";
}

function countLabel(count, singular, plural = `${singular}들`) {
  return `${count}${count === 1 ? singular : plural}`;
}

function say(message, isError = false) {
  const node = $("message");
  node.textContent = message;
  node.style.color = isError ? "#ff9b8e" : "";
}

function appendChatMessage(role, message) {
  const root = $("chat-messages");
  if (!root || !message) return;
  const article = document.createElement("article");
  article.className = `chat-message ${role}`;
  const avatar = document.createElement("div");
  avatar.className = "chat-avatar";
  avatar.textContent = role === "user" ? "나" : "CG";
  const bubble = document.createElement("div");
  bubble.className = "chat-bubble";
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  bubble.appendChild(paragraph);
  article.append(avatar, bubble);
  root.appendChild(article);
  root.scrollTop = root.scrollHeight;
}

function chatReply(message) {
  appendChatMessage("assistant", message);
}

async function submitChat(event) {
  event?.preventDefault();
  const input = $("chat-input");
  const text = input?.value.trim();
  if (!text) {
    say("먼저 작업 내용을 입력하세요.", true);
    input?.focus();
    return;
  }
  appendChatMessage("user", text);
  $("task").value = text;
  input.value = "";
  invalidateRoutePlan();
  chatReply("작업 내용을 확인했습니다. 로컬 사전 분석을 실행해 위험도와 관련 파일을 확인하겠습니다.");
  const result = await makePreflight();
  if (result) {
    chatReply(`사전 분석이 끝났습니다. 위험도 ${result.risk}, 관련 파일 ${result.candidate_files}개, 예상 컨텍스트 ${Number(result.estimated_context || 0).toLocaleString()}토큰입니다. 아래 작업 카드에서 범위와 권한을 조정할 수 있습니다.`);
  }
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || "요청에 실패했습니다.");
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
    model.appendChild(option("", "연결된 모델 없음", true));
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
    effort.appendChild(option("", "지원되는 추론 강도 없음", true));
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
  if (typeof value !== "number") return "확인 전";
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
  const used = typeof primary?.usedPercent === "number" ? `${primary.usedPercent}%` : "확인 전";
  $("account-state").textContent = statusLabel(overview?.account_state);
  $("account-auth").textContent = `${account.auth_mode || "확인 전"} / ${account.plan_type || "확인 전"}`;
  $("account-used").textContent = used;
  $("account-reset").textContent = formatReset(primary?.resetsAt);
  $("account-meta").textContent = `계정 rate-limit: ${statusLabel(limits.status)}; 이메일: ${account.email_masked || "저장하지 않음"}; 모델별 잔여량이 아닙니다.`;
  const daily = Array.isArray(usage.daily) ? usage.daily : [];
  const tokens = daily.reduce((total, entry) => total + (Number.isFinite(entry.tokens) ? entry.tokens : 0), 0);
  $("usage-meta").textContent = usage.status === "AVAILABLE"
    ? `일별 토큰 사용량 ${daily.length}일 / ${tokens.toLocaleString()}토큰 (일별 요약만 저장)`
    : "일별 토큰 사용량: 확인 전";
}

function renderCatalog(entries) {
  const body = $("model-catalog");
  body.replaceChildren();
  for (const entry of entries || []) {
    const row = document.createElement("tr");
    appendCell(row, `${entry.display_name || entry.id} (${entry.id})`);
    appendCell(row, (entry.efforts || []).join(" → ") || "확인 전");
    appendCell(row, (entry.speed_tiers || []).map((tier) => tier.name || tier.id).join(", ") || "—");
    const statusCell = document.createElement("td");
    const select = document.createElement("select");
    for (const state of ["AVAILABLE", "LIMITED", "DEPLETED", "UNKNOWN", "DISABLED"]) {
      select.appendChild(option(state, statusLabel(state), state === entry.status));
    }
    select.onchange = async () => {
      try {
        const data = await api(`/api/models/${encodeURIComponent(entry.id)}/status`, {
          method: "POST",
          body: JSON.stringify({ status: select.value }),
        });
        renderCatalog(data.model_catalog);
      say(`모델 ${entry.id}의 수동 상태를 ${statusLabel(select.value)}(으)로 변경했습니다.`);
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
  appendCell(row, statusLabel(result.status));
  appendCell(row, `${recommendation.model || "—"} / ${recommendation.effort || "—"}`);
  appendCell(row, final.model ? `${final.model} / ${final.effort}` : "보류");
  appendCell(row, (result.candidate_ladder || []).map((candidate) => `${candidate.model}${candidate.effort ? `/${candidate.effort}` : ""} [${statusLabel(candidate.status)}]: ${candidate.selection_reason}`).join("\n") || "—");
  appendCell(row, [...(result.downgrade_reasons || []), ...(result.hold_reasons || []), ...(result.warnings || [])].join(" ") || "변경 없음.");
  const policy = result.policy_input || {};
  const maximum = result.account_usage_evidence?.maximum_used_percent;
  appendCell(row, `계정 ${statusLabel(result.account_state)}${typeof maximum === "number" ? ` (${maximum}%)` : ""}\n파일 ${policy.file_count ?? "—"}\n테스트 ${policy.has_tests ? "있음" : "없음"}\n${policy.read_only ? "읽기 전용" : "쓰기"}`);
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
    say(data.status === "HOLD" ? "라우터 미리보기가 보류되었습니다. 실행 설정은 변경되지 않았습니다." : "라우터 미리보기를 생성했습니다. 실행 설정은 변경되지 않았습니다.", data.status === "HOLD");
  } catch (error) {
    say(error.message, true);
  }
}

async function connect() {
  try {
    say("Codex app-server에 연결하는 중입니다…");
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
    $("connection-text").textContent = `${data.choices.length}개 모델 연결됨`;
    $("codex-meta").textContent = `${data.codex_version || "버전 확인 불가"} · ${data.codex_path || "경로 확인 불가"}`;
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
        ? "연결되었습니다. 작업 폴더 쓰기가 준비되었습니다."
        : "연결되었습니다. 스키마 점검이 끝날 때까지 작업 폴더 쓰기는 잠겨 있습니다.",
      !data.workspace_write_available,
    );
    chatReply(data.workspace_write_available
      ? "Codex 연결이 완료되었습니다. 작업 폴더 쓰기 상태도 준비되어 있습니다."
      : "Codex 연결이 완료되었습니다. 안전을 위해 작업 폴더 쓰기는 아직 잠겨 있습니다.");
  } catch (error) {
    say(error.message, true);
  }
}

function planIsExecutable() {
  return false;
}

function renderIsolation(result) {
  isolationStatus = result?.status || "UNKNOWN";
  $("isolation-status").textContent = statusLabel(isolationStatus);
  let outside = "외부 읽기가 실패했거나 확인되지 않음";
  if (result?.outside_read_succeeded === true) {
    outside = "외부 읽기 성공";
  } else if (result?.outside_denied_explicitly === true) {
    outside = "외부 읽기가 명시적으로 거부됨";
  }
  const errorCode = result?.error_code ? `; 오류 코드=${result.error_code}` : "";
  $("isolation-result").textContent = `상태: ${statusLabel(isolationStatus)} (${isolationStatus}); ${outside}${errorCode}. 이 버전에서는 실제 실행이 잠겨 있습니다.`;
  updateExecuteState();
}

function renderWSLIsolation(result) {
  wslIsolationStatus = result?.status || "UNCONFIGURED";
  $("wsl-isolation-status").textContent = statusLabel(wslIsolationStatus);
  if (result?.distro) $("wsl-isolation-distro").value = result.distro;
  const environmentText = result?.environment_changed ? " 환경이 바뀌어 캐시 결과를 무효화했습니다." : "";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  $("wsl-isolation-result").textContent = `상태: ${statusLabel(wslIsolationStatus)} (${wslIsolationStatus}).${code}${environmentText} 이 버전에서는 실제 실행이 잠겨 있습니다.`;
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
  node.textContent = `반복성 점검: ${success}/${completed || 10}회 성공; 최종 상태 ${statusLabel(status)} (${status}). 실제 실행은 잠겨 있습니다.`;
}

function renderWSLCodexRuntime(result) {
  wslRuntimeStatus = result?.status || "UNCONFIGURED";
  const statusNode = $("wsl-runtime-status");
  const detailNode = $("wsl-runtime-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = statusLabel(wslRuntimeStatus);
  const configured = result?.binary_configured === true ? "설정됨" : "설정되지 않음";
  const version = result?.version_match === true ? "0.145.0 일치" : "불일치";
  const isolation = result?.isolation_match === true ? "WSL 격리 일치" : "WSL 격리 불일치";
  const fingerprint = result?.runtime_fingerprint ? "기록됨" : "확인 불가";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  detailNode.textContent = `바이너리 ${configured}; 버전 ${version}; 런타임 지문 ${fingerprint}; ${isolation}; 외부 통신은 차단되어 있습니다.${code} Codex 시작은 잠겨 있습니다.`;
}

function renderSealedEgressContract(result) {
  wslEgressStatus = result?.status || "UNCONFIGURED";
  const statusNode = $("wsl-egress-status");
  const detailNode = $("wsl-egress-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = statusLabel(wslEgressStatus);
  const endpoint = result?.endpoint_type || "미설정";
  const contract = result?.contract_hash ? "기록됨" : "기록되지 않음";
  const relay = result?.relay_status || "RELAY_MISSING";
  const broker = result?.broker_status || "BROKER_MISSING";
  const auth = result?.auth_status || "AUTH_UNCONFIGURED";
  const lifecycle = result?.reused ? " 기존 계약을 재사용했습니다." : result?.created ? " 새 계약을 생성했습니다." : "";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  detailNode.textContent = `엔드포인트 ${endpoint}; 계약 해시 ${contract}; 릴레이 ${relay}; 브로커 ${broker}; 인증 ${auth}.${lifecycle}${code} 네트워크와 Codex 시작은 잠겨 있습니다.`;
}

function renderSealedEgressHarness(result) {
  wslHarnessStatus = result?.status || "BLOCKED";
  const statusNode = $("wsl-harness-status");
  const detailNode = $("wsl-harness-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = `가짜 실행: ${statusLabel(wslHarnessStatus)}`;
  const hash = result?.contract_hash ? "변경 불가 계약 일치" : "실행 가능한 계약 없음";
  const resultHash = result?.response_hash ? "결정적 응답 기록됨" : "응답 본문 저장 없음";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  detailNode.textContent = `가짜 실행 ${statusLabel(wslHarnessStatus)}; ${hash}; ${resultHash}. 이 결과는 실제 WSL 증명으로 재사용하지 않습니다.${code}`;
  const button = $("run-wsl-egress-harness");
  if (button) button.disabled = wslHarnessStatus !== "READY";
}

function renderActualWSLEgressHarness(result) {
  actualWSLHarnessStatus = result?.status === "PASSED" ? "PASSED" : "NOT RUN";
  const statusNode = $("actual-wsl-harness-status");
  const detailNode = $("actual-wsl-harness-result");
  if (!statusNode || !detailNode) return;
  statusNode.textContent = `WSL ${statusLabel(actualWSLHarnessStatus)}`;
  const proof = result?.status === "READY" ? "현재 Canary와 Repro 증명이 일치함" : "증명 또는 계약이 준비되지 않음";
  const implementation = result?.runner_implementation_hash ? "실행기 구현이 봉인됨" : "실행기 구현 확인 불가";
  const window = result?.execution_window || { status: "DISABLED", remaining_seconds: 0 };
  const windowState = window.status || "DISABLED";
  const remaining = windowState === "ARMED" ? ` ${window.remaining_seconds || 0}초 남음.` : "";
  const binding = window.binding_hash ? ` 바인딩 ${window.binding_hash.slice(0, 16)}…` : "";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  detailNode.textContent = `실제 WSL: ${statusLabel(actualWSLHarnessStatus)}; ${proof}; ${implementation}. 창 상태 ${statusLabel(windowState)} (${windowState}).${remaining}${binding}${code} 이 창은 하니스 요청 1회만 허용하며 런타임과 실제 실행은 잠겨 있습니다.`;
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
  const permitRemaining = permit.status === "ARMED" ? ` ${permit.remaining_seconds || 0}초 남음.` : "";
  const remaining = window.status === "ARMED" ? ` ${window.remaining_seconds || 0}초 남음.` : "";
  const implementation = result?.implementation_hash ? "구현 봉인됨" : "실행 가능한 구현 없음";
  const code = result?.error_code ? ` 오류 코드: ${result.error_code}.` : "";
  statusNode.textContent = statusLabel(status);
  const claim = result?.execution_claim || { status: "DISABLED" };
  detailNode.textContent = `오프라인 Codex Canary ${statusLabel(status)}; ${implementation}. 서버 Permit ${statusLabel(permit.status)}.${permitRemaining} Canary 창 ${statusLabel(window.status)}.${remaining} 1회용 청구 ${statusLabel(claim.status)}.${code} 로컬 클릭 한 번으로 봉인된 전달을 완료하며 외부 모델 토큰은 0이고 런타임과 실제 실행은 잠겨 있습니다.`;
  const runButton = $("run-codex-process-canary-one-shot");
  if (runButton) {
    // The integrated endpoint refreshes a near-expiry isolation proof inside
    // the same server handoff.  Keep other blocked reasons fail-closed.
    const refreshableIsolation = result?.reason_code === "isolation_expiring";
    runButton.disabled = !refreshableIsolation && (result?.permit_ready !== true
      || (result?.readiness !== true && !["READY", "DISABLED"].includes(status)));
  }
}

async function refreshOfflineCodexCanaryReadiness() {
  try {
    const readiness = await api("/api/isolation/wsl/codex-process-canary/readiness");
    renderCodexProcessCanary({
      ...readiness,
      readiness: true,
      execution_permit: { status: "DISABLED", remaining_seconds: 0 },
      execution_window: { status: "DISABLED", remaining_seconds: 0 },
      execution_claim: { status: "DISABLED" },
    });
    if (readiness.reason_code) say("오프라인 Canary 준비 상태: " + readiness.reason_code + ".", true);
  } catch (error) {
    say(error.message, true);
  }
}

async function runIsolationProbe() {
  try {
    $("run-isolation-probe").disabled = true;
    say("모델 턴을 시작하지 않고 app-server 읽기 격리를 점검하는 중입니다…");
    const result = await api("/api/isolation/probe", { method: "POST" });
    renderIsolation(result);
    say(`격리 점검 결과를 기록했습니다: ${statusLabel(result.status)} (${result.status}). 실제 실행은 잠겨 있습니다.`, result.status !== "SAFE_CANDIDATE");
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
    say("WSL 배포판을 저장했습니다. 준비되면 고정 bwrap 사전 점검을 실행하세요.");
  } catch (error) {
    say(error.message, true);
  }
}

async function runWSLIsolationProbe() {
  try {
    $("run-wsl-isolation-probe").disabled = true;
    say("app-server나 모델 턴 없이 고정 WSL2+bubblewrap 카나리를 실행하는 중입니다…");
    const result = await api("/api/isolation/wsl/probe", { method: "POST" });
    renderWSLIsolation(result);
    // A successful probe is not readiness. Read the current DB-backed
    // readiness exactly once, then continue only when every sealed proof is
    // fresh and bound to the same environment.
    if (result.status === "SAFE_CANDIDATE") {
      const readiness = await api("/api/isolation/wsl/codex-process-canary/readiness");
      renderCodexProcessCanary({
        ...readiness,
        readiness: true,
        execution_permit: { status: "DISABLED", remaining_seconds: 0 },
        execution_window: { status: "DISABLED", remaining_seconds: 0 },
        execution_claim: { status: "DISABLED" },
      });
      const requiredRemaining = Number(readiness.offline_canary_min_remaining_seconds || 0);
      if (readiness.status !== "READY" || Number(readiness.remaining_seconds || 0) <= requiredRemaining) {
        const detail = readiness.reason_code === "isolation_expiring"
          ? `발급 시각=${readiness.issued_at || "확인 불가"}, 만료 시각=${readiness.expires_at || "확인 불가"}, 남은 시간(초)=${Number(readiness.remaining_seconds || 0)}`
          : (readiness.reason_code || readiness.status || "readiness_blocked");
        say(`오프라인 Canary 준비 조건이 차단되었습니다: ${detail}.`, true);
      }
    } else {
      say(`WSL 격리 점검 결과를 기록했습니다: ${statusLabel(result.status)} (${result.status}). 실제 실행은 잠겨 있습니다.`, true);
    }
  } catch (error) {
    say(error.message, true);
  } finally {
    $("run-wsl-isolation-probe").disabled = false;
  }
}

async function runWSLIsolationRepro() {
  try {
    $("run-wsl-isolation-repro").disabled = true;
    say("모델 턴 없이 고정 WSL 점검 10회를 실행하는 중입니다…");
    const result = await api("/api/isolation/wsl/repro", { method: "POST" });
    renderWSLRepro(result);
    say(`WSL 반복성 점검: ${statusLabel(result.status)} (${result.status}). 실제 실행은 잠겨 있습니다.`, result.status !== "SAFE_REPRODUCIBLE");
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
    say("WSL Codex 바이너리 선택을 비공개로 저장했습니다. Codex를 시작하지 않고 메타데이터를 검증하세요.");
  } catch (error) {
    say(error.message, true);
  }
}

async function runWSLCodexRuntimePreflight() {
  try {
    $("run-wsl-runtime-preflight").disabled = true;
    say("선택한 WSL 바이너리의 메타데이터만 검증합니다. Codex 프로세스는 시작하지 않습니다…");
    const result = await api("/api/isolation/wsl/runtime/preflight", { method: "POST" });
    renderWSLCodexRuntime(result);
    say(`봉인 런타임 검증: ${statusLabel(result.status)} (${result.status}). 외부 통신과 Codex 시작은 잠겨 있습니다.`, result.status !== "EGRESS_UNCONFIGURED");
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
    say("변경 불가 인스턴스를 만들기 전에 봉인 계약 미리보기를 새로 확인하는 중입니다…");
    const preview = await api("/api/isolation/wsl/egress-contract/preview");
    if (!preview.preview_hash) throw new Error(preview.error_code || "계약 미리보기가 준비되지 않았습니다.");
    const result = await api("/api/isolation/wsl/egress-contract", {
      method: "POST",
      body: JSON.stringify({ expected_preview_hash: preview.preview_hash }),
    });
    renderSealedEgressContract(result);
    renderSealedEgressHarness(await api("/api/isolation/wsl/egress-harness"));
    renderActualWSLEgressHarness(await api("/api/isolation/wsl/egress-harness/actual"));
    renderCodexProcessCanary(await api("/api/isolation/wsl/codex-process-canary"));
    const lifecycle = result.reused ? "기존 계약을 재사용했습니다." : result.created ? "새 계약을 생성했습니다." : "";
    say(`봉인 외부 통신 계약: ${statusLabel(result.status)} (${result.status}). ${lifecycle} 인증과 모든 시작은 잠겨 있습니다.`, result.status !== "AUTH_UNCONFIGURED");
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
    say("2분짜리 1회용 WSL 하니스 창을 로컬에서 열었습니다. 다음 실제 하니스 요청이 두 capability를 모두 소비합니다.");
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

async function runOfflineCodexOneShot() {
  const button = $("run-codex-process-canary-one-shot");
  if (button) button.disabled = true;
  try {
    const result = await api("/api/isolation/wsl/codex-process-canary/execute-one-shot", { method: "POST", headers: {} });
    renderCodexProcessCanary(result);
    say("오프라인 Canary를 1회 완료했습니다. 외부 모델 토큰은 계속 0입니다.");
    chatReply(`오프라인 Canary 결과: ${statusLabel(result.status)}. 외부 모델 토큰은 0이며 봉인된 로컬 검증만 수행했습니다.`);
  } catch (error) {
    // The server has already consumed or aborted its internal capabilities;
    // never re-enable this one-shot button after any response.
    say(error.message, true);
    chatReply(`오프라인 Canary를 완료하지 못했습니다: ${error.message}`);
  }
}

async function runSealedEgressHarness() {
  const button = $("run-wsl-egress-harness");
  try {
    button.disabled = true;
    say("결정적 인메모리 하니스만 실행합니다. 3단계 WSL 실행기는 선택되지 않았으므로 WSL, 소켓, 네트워크, Codex, 모델 프로세스는 시작하지 않습니다…");
    const result = await api("/api/isolation/wsl/egress-harness", { method: "POST" });
    renderSealedEgressHarness(result);
    say(`봉인 외부 통신 가짜 하니스: ${statusLabel(result.status)} (${result.status}). 인증과 모든 실제 시작은 잠겨 있습니다.`, result.status !== "PASSED");
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
  $("capsule-status").textContent = "생성 전";
  $("capsule-files").textContent = "0";
  $("capsule-size").textContent = "0바이트";
  $("capsule-ranges").textContent = "없음";
  $("capsule-reasons").textContent = "";
  $("create-capsule").disabled = !currentPlan;
}

function renderCapsule(capsule) {
  currentCapsule = capsule;
  $("capsule-status").textContent = statusLabel(capsule.status);
  $("capsule-files").textContent = String(capsule.file_count || 0);
  $("capsule-size").textContent = `${Number(capsule.total_bytes || 0).toLocaleString()}바이트`;
  const ranges = capsule.ranges || [];
  $("capsule-ranges").textContent = ranges.length
    ? ranges.map((entry) => `${entry.path}:${entry.start_line}-${entry.end_line}`).join(", ")
    : "없음";
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
  $("plan-status").textContent = statusLabel(plan.status);
  $("plan-id").textContent = plan.plan_id;
  $("plan-hash").textContent = plan.decision_hash;
  $("plan-expiry").textContent = new Date(plan.expires_at).toLocaleString();
  $("plan-final").textContent = plan.final ? `${plan.final.model} / ${plan.final.effort}` : "보류";
  $("plan-budget").textContent = plan.budget
    ? `${plan.budget_level} · ${Number(plan.budget.tokens).toLocaleString()}토큰 / ${plan.budget.tools}개 도구 / ${plan.budget.changed_files}개 파일`
    : "—";
  $("planned-budget").value = plan.budget
    ? `${plan.budget_level} · ${Number(plan.budget.tokens).toLocaleString()}토큰`
    : "보류";
  $("plan-scope").textContent = `${plan.planned_file_count}개 파일(정확히 지정됨)`;
  const evidence = plan.validation_evidence || {};
  $("plan-validation").textContent =
    `검증 명령=${Boolean(evidence.validation_commands_present)}, 로컬 대상=${Boolean(evidence.local_test_target_exists)}`;
  $("plan-reasons").textContent = (plan.hold_reasons || []).join("\n");
  resetCapsule();
  updateExecuteState();
  if (planExpiryTimer) clearTimeout(planExpiryTimer);
  const delay = Math.max(0, Date.parse(plan.expires_at) - Date.now());
  planExpiryTimer = setTimeout(() => {
    updateExecuteState();
    say("Route Plan이 만료되었습니다. 실행 전에 새 계획을 생성하세요.", true);
  }, Math.min(delay + 50, 2_147_483_647));
}

async function createCapsule() {
  try {
    if (!currentPlan) {
      throw new Error("증거 캡슐을 만들기 전에 Route Plan을 생성하세요.");
    }
    say("제한된 증거 캡슐을 생성하는 중입니다…");
    const capsule = await api(`/api/route-plans/${encodeURIComponent(currentPlan.plan_id)}/capsule`, { method: "POST" });
    renderCapsule(capsule);
    say(
      capsule.status === "READY" ? "Codex를 시작하지 않고 증거 캡슐을 생성했습니다." : "증거 캡슐이 보류 또는 무효 상태입니다.",
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
    say("변경 불가 Route Plan을 생성하는 중입니다…");
    const plan = await api("/api/route-plans", { method: "POST", body: JSON.stringify(payload) });
    renderRoutePlan(plan);
    renderRoutePreview(plan.route_preview);
    say(
      plan.status === "PREVIEW" ? "Route Plan을 생성했습니다. 이 버전에서는 실제 실행이 계속 잠겨 있습니다." : "Route Plan이 보류 상태입니다.",
      plan.status !== "PREVIEW",
    );
  } catch (error) {
    invalidateRoutePlan();
    say(error.message.includes("JSON") ? "결정 JSON이 올바르지 않습니다." : error.message, true);
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
    $("context").textContent = `${data.estimated_context.toLocaleString()}토큰`;
    $("git-status").textContent = `Git 상태: ${data.git_status}`;
    $("web-packet").value = data.web_packet;
    say("사전 분석 패킷을 생성했습니다.");
    return data;
  } catch (error) {
    say(error.message, true);
    chatReply(`사전 분석을 완료하지 못했습니다: ${error.message}`);
    return null;
  }
}

async function copyPacket() {
  try {
    await navigator.clipboard.writeText($("web-packet").value);
    say("사전 분석 패킷을 클립보드에 복사했습니다.");
  } catch {
    say("이 브라우저에서는 클립보드 복사를 사용할 수 없습니다.", true);
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
  title.textContent = `승인 요청 · ${approval.kind}`;

  const dl = document.createElement("dl");
  const pairs = [
    ["명령", approval.command || "—"],
    ["작업 폴더", approval.cwd || "—"],
    ["파일", (approval.paths || []).join(", ") || "—"],
    ["사유", approval.reason || "—"],
    ["권한", approval.permissions ? JSON.stringify(approval.permissions, null, 2) : "—"],
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
    accept: "이번 한 번 허용",
    acceptForSession: "이 세션 동안 허용",
    decline: "거부",
    cancel: "취소",
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
  $("run-status").textContent = statusLabel(run.status);
  $("run-tokens").textContent = `${run.tokens.toLocaleString()} / ${run.budget.tokens.toLocaleString()}`;
  $("run-tools").textContent = `${run.tool_calls} / ${run.budget.tools}`;
  $("run-files").textContent = `${run.changed_files.length} / ${run.budget.changed_files}`;
  $("run-failures").textContent = `${run.failed_commands}개 명령 / ${run.failed_tests}개 테스트`;
  $("run-model").textContent = `${run.model} / ${run.effort}`;
  $("events").textContent = run.events.join("\n") || "이벤트를 기다리는 중…";
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
    say(`승인 응답을 보냈습니다: ${decision}`);
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
      say("이벤트 스트림 연결이 끊겼습니다.", true);
    }
  };
}

async function execute() {
  try {
    if (!planIsExecutable()) {
      throw new Error("이 버전에서는 실제 실행이 잠겨 있습니다.");
    }
    const payload = {
      route_plan_id: currentPlan.plan_id,
    };
    say("Codex 실행을 생성하는 중입니다…");
    const run = await api("/api/run", { method: "POST", body: JSON.stringify(payload) });
    renderRun(run);
    watch(run.id);
    currentPlan.used = true;
    updateExecuteState();
    say("실행을 시작했습니다.");
  } catch (error) {
    say(error.message.includes("JSON") ? "결정 JSON이 올바르지 않습니다." : error.message, true);
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
    say("브리지 작업을 생성했습니다. 아키텍처 패킷을 복사하세요.");
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
    say("패킷을 복사했고 설정된 웹 GPT URL을 새 탭에서 열었습니다.");
  } catch {
    bridgeManualMode = "mark-copied";
    renderBridge(currentBridge);
    say("클립보드 복사에 실패했습니다. 접힌 패킷을 직접 복사한 뒤 확인하세요.", true);
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
      say("클립보드 읽기에 실패했습니다. 수동 입력란에 응답 패킷을 붙여넣으세요.", true);
      return;
    }
  }
  const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/import`, {
    method: "POST", body: JSON.stringify({ packet }),
  });
  $("bridge-manual-response").value = "";
  bridgeManualMode = null;
  renderBridge(bridge);
  say("웹 GPT 응답을 검증하고 기록했습니다.");
}

async function prepareBridgeReview() {
  const result = JSON.parse($("bridge-result").value);
  const validation = JSON.parse($("bridge-validation").value);
  const bridge = await api(`/api/bridge/tasks/${encodeURIComponent(currentBridge.task_id)}/review`, {
    method: "POST", body: JSON.stringify({ result, validation }),
  });
  renderBridge(bridge);
  say("검토 패킷을 복사할 준비가 되었습니다.");
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
        throw new Error("현재 브리지 작업을 사용할 수 없습니다.");
    }
  } catch (error) {
    say(error.message.includes("JSON") ? "브리지 결과와 검증 내용은 올바른 JSON이어야 합니다." : error.message, true);
  }
}

function bridgePresentation(bridge) {
  const actions = {
    copy_architect_request: ["로컬 → 웹 GPT", "ARCHITECT_REQUEST", "아키텍처 패킷을 복사하세요.", "응답을 가져오세요.", "send"],
    import_architect_response: ["웹 GPT → 로컬", "ARCHITECT_RESPONSE", "아키텍처 응답을 가져오세요.", "앱이 로컬에서 검증합니다.", "receive"],
    prepare_review_request: ["로컬 → 로컬", "REVIEW_REQUEST", "실제 결과와 검증 내용을 입력하세요.", "검토 패킷을 복사하세요.", "auto"],
    processing_response: ["웹 GPT → 로컬", bridge?.packet_type || "-", "붙여넣은 응답을 로컬에서 검증하는 중입니다.", "업데이트된 상태를 기다리세요.", "auto"],
    prepare_evidence: ["로컬 → 로컬", "EVIDENCE_REQUIRED", "각 요청을 프로젝트 상대 경로의 정확한 파일에 매핑하고 수집하세요.", "필수 증거가 준비되면 새 ARCHITECT_REQUEST가 활성화됩니다.", "auto"],
    copy_review_request: ["로컬 → 웹 GPT", "REVIEW_REQUEST", "검토 패킷을 복사하세요.", "검토 응답을 가져오세요.", "send"],
    import_review_response: ["웹 GPT → 로컬", "REVIEW_RESPONSE", "검토 응답을 가져오세요.", "앱이 판정을 기록합니다.", "receive"],
    restart: ["로컬 → 웹 GPT", "ARCHITECT_REQUEST", "새 아키텍처 사이클을 시작하세요.", "새 nonce와 Route Plan이 필요합니다.", bridge.status === "SUCCESS" ? "done" : "hold"],
    restart_required: ["로컬", "v1", "이 v1 작업은 변환할 수 없습니다.", "새 v2 브리지 작업을 시작하세요.", "hold"],
  };
  return actions[bridge?.active_action] || ["로컬", "-", "사용 가능한 작업이 없습니다.", "새 브리지 작업을 시작하세요.", "idle"];
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
    input.type = "text"; input.placeholder = "프로젝트 상대 경로"; input.value = request.mapped_path || "";
    const map = document.createElement("button");
    map.type = "button"; map.className = "button ghost"; map.textContent = "로컬 파일 매핑";
    const collect = document.createElement("button");
    collect.type = "button"; collect.className = "button"; collect.textContent = "안전한 요약 수집";
    map.onclick = async () => {
      try { renderBridge(await api(`/api/bridge/tasks/${encodeURIComponent(bridge.task_id)}/evidence/${encodeURIComponent(request.request_id)}/map`, {method:"POST", body: JSON.stringify({path: input.value})})); } catch (error) { say(error.message, true); }
    };
    collect.disabled = request.state !== "MAPPED" && request.state !== "FAILED";
    collect.onclick = async () => {
      try { renderBridge(await api(`/api/bridge/tasks/${encodeURIComponent(bridge.task_id)}/evidence/${encodeURIComponent(request.request_id)}/collect`, {method:"POST"})); } catch (error) { say(error.message, true); }
    };
    const status = document.createElement("small");
    status.textContent = request.error_reason || (request.required ? "필수 증거" : "선택 증거");
    card.append(title, why, input, map, collect, status); panel.appendChild(card);
  }
}

function renderBridge(bridge) {
  currentBridge = bridge;
  const start = $("bridge-start");
  const action = $("bridge-action");
  if (!bridge) {
    $("bridge-status").textContent = "시작 전";
    $("bridge-status").className = "status bridge-flag idle";
    $("bridge-phase").textContent = "-";
    $("bridge-source").textContent = "로컬";
    $("bridge-destination").textContent = "웹 GPT";
    $("bridge-type").textContent = "-";
    $("bridge-now").textContent = "브리지 작업을 시작하세요.";
    $("bridge-next").textContent = "아키텍처 패킷을 복사하세요.";
    $("bridge-message").textContent = "진행 중인 브리지 작업이 없습니다.";
    start.disabled = false; start.classList.remove("hidden"); action.disabled = true; action.classList.add("hidden");
    $("bridge-review-fields").classList.add("hidden");
    $("bridge-evidence").classList.add("hidden");
    return;
  }
  const [direction, type, now, next, color] = bridgePresentation(bridge);
  const [source, destination] = direction.split(" -> ");
  $("bridge-status").textContent = statusLabel(bridge.status);
  $("bridge-status").className = `status bridge-flag ${color}`;
  $("bridge-phase").textContent = bridge.phase || "-";
  $("bridge-source").textContent = source || "로컬";
  $("bridge-destination").textContent = destination || "로컬";
  $("bridge-type").textContent = type;
  $("bridge-now").textContent = now;
  $("bridge-next").textContent = next;
  $("bridge-message").textContent = bridge.restart_required
    ? "프로토콜 v1은 재시작이 필요하며 변환되지 않았습니다."
    : bridge.active_action === "processing_response"
      ? "붙여넣은 응답을 로컬에서 검증하는 중입니다."
      : bridge.hold_reason || (bridge.requested_evidence?.length ? `요청된 증거: ${bridge.requested_evidence.map((item) => item.label || item).join("; ")}` : "화면에 표시된 작업만 활성화되어 있습니다.");
  start.disabled = true; start.classList.add("hidden"); action.classList.remove("hidden");
  action.disabled = ["prepare_evidence", "restart_required", "processing_response"].includes(bridge.active_action);
  const labels = {copy_architect_request:"아키텍처 패킷 복사", import_architect_response: bridgeManualMode === "import" ? "붙여넣은 아키텍처 응답 가져오기" : "아키텍처 응답 읽고 가져오기", prepare_review_request:"로컬 결과로 검토 패킷 생성", processing_response:"응답 처리 중", prepare_evidence:"아래 필수 증거 준비", copy_review_request:"검토 패킷 복사", import_review_response: bridgeManualMode === "import" ? "붙여넣은 검토 응답 가져오기" : "검토 응답 읽고 가져오기", restart:"새 아키텍처 사이클 시작", restart_required:"새 v2 브리지 작업 시작"};
  action.textContent = bridgeManualMode === "mark-copied" ? "패킷을 수동으로 복사 완료 표시" : labels[bridge.active_action] || "사용할 수 없음";
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
    $("bridge-recent").textContent = tasks.length ? `진행 중인 브리지 작업 ${tasks.length}개를 복구했습니다. 최신 작업을 표시합니다.` : "복구할 미완료 브리지 작업이 없습니다.";
    if (data.latest) { bridgeManualMode = null; renderBridge(data.latest); await showBridgePacket(data.latest.task_id); }
  } catch { $("bridge-recent").textContent = "브리지 복구를 사용할 수 없습니다."; }
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
  $("catalog-scan-status").textContent = statusLabel(scan.status);
  $("catalog-progress").textContent = `${currentCatalogSource?.alias || "원본"}: 파일 ${metrics.files_seen || 0}개, 색인 바이트 ${metrics.bytes_indexed || 0}, 읽은 본문 바이트 ${metrics.content_bytes_read || 0}; 추가 ${metrics.added || 0}, 수정 ${metrics.modified || 0}, 누락 ${metrics.missing || 0}, 거부 ${metrics.rejected || 0}.`;
  $("catalog-scan").disabled = false;
  $("catalog-resume").disabled = scan.status !== "INTERRUPTED";
  $("catalog-cancel").disabled = true;
}

function updateCatalogProbeButton() {
  const count = selectedCatalogEntries.size;
  $("catalog-probe").disabled = !currentCatalogSource || count === 0 || count > 50;
  $("catalog-probe-summary").textContent = count
    ? `카탈로그 항목 ${count}개를 선택했습니다. 점검은 제한된 헤더/샘플 바이트만 읽으며 절대 경로를 반환하지 않습니다.`
    : "카탈로그 항목을 최대 50개 선택하세요. 2단계에서는 파일의 제한된 영역만 샘플링하며 전체 파일을 분석하지 않습니다.";
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
    $("catalog-progress").textContent = `${source.alias} 원본을 등록했습니다. 로컬 경로는 비공개로 유지됩니다.`;
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
    $("catalog-scan-status").textContent = "스캔 중";
    const action = resume ? "resume" : "scan";
    const scan = await api(`/api/catalog/sources/${encodeURIComponent(currentCatalogSource.source_id)}/${action}`, {method: "POST", body: JSON.stringify({})});
    renderCatalogScan(scan);
    await refreshCatalogEntries();
  } catch (error) { $("catalog-scan-status").textContent = "실패"; $("catalog-scan").disabled = false; say(error.message, true); }
}

async function cancelCatalog() {
  if (!currentCatalogSource) return;
  try {
    await api(`/api/catalog/sources/${encodeURIComponent(currentCatalogSource.source_id)}/cancel`, {method: "POST"});
    $("catalog-progress").textContent = "취소를 요청했습니다. 현재 메타데이터 묶음을 안전하게 마무리합니다.";
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
    say(`카탈로그 항목 ${(data.results || []).length}개의 형식 점검을 완료했습니다.`);
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
  const quality = record.quality || "확인 전";
  return `${processed} (${quality})`;
}

function renderTokenLedger(report) {
  const summary = report?.summary || {};
  const usage = report?.usage_totals || {};
  $("ledger-summary-status").textContent = summary.comparison_count ? "활성" : "데이터 없음";
  $("ledger-summary-message").textContent = summary.message || "비교 가능한 절감 데이터가 없습니다.";
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
    appendCell(row, statusLabel(comparison.status || "NOT_COMPARABLE"));
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
    $("ledger-summary-message").textContent = `${summary.message || "비교 가능한 절감 데이터가 없습니다."} 브리지=${usage.web_packet_bytes || 0}, 증거=${usage.evidence_bytes || 0}, 카탈로그=${usage.catalog_source_bytes || 0}, 점검=${usage.probe_bytes || 0}`;
  }
}

async function refreshTokenLedger() {
  try {
    const report = await api("/api/token-ledger/report");
    renderTokenLedger(report);
  } catch (error) {
    $("ledger-summary-status").textContent = "오류";
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
    say("토큰 원장 기준선을 가져왔습니다.");
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
    if (!response.ok) throw new Error(text || "내보내기에 실패했습니다.");
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
$("connect").onclick = connect;
$("preflight").onclick = () => makePreflight();
$("router-preview").onclick = previewRouter;
$("copy-packet").onclick = copyPacket;
$("create-plan").onclick = createRoutePlan;
$("create-capsule").onclick = createCapsule;
$("execute").onclick = execute;
$("interrupt").onclick = interrupt;
$("bridge-start").onclick = startBridge;
$("bridge-action").onclick = bridgeAction;
$("catalog-register").onclick = registerCatalogSource;
$("catalog-scan").onclick = () => scanCatalog(false);
$("catalog-resume").onclick = () => scanCatalog(true);
$("catalog-cancel").onclick = cancelCatalog;
$("catalog-probe").onclick = runFormatProbe;
$("chat-composer").addEventListener("submit", submitChat);
$("chat-input").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    $("chat-composer").requestSubmit();
  }
});
for (const suggestion of document.querySelectorAll(".chat-suggestion")) {
  suggestion.addEventListener("click", () => {
    $("chat-input").value = suggestion.dataset.prompt || "";
    $("chat-input").focus();
  });
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
$("run-codex-process-canary-one-shot").onclick = runOfflineCodexOneShot;
refreshOfflineCodexCanaryReadiness();
for (const id of ["catalog-filter-status", "catalog-filter-kind", "catalog-filter-extension"]) $(id).addEventListener("change", () => refreshCatalogEntries().catch((error) => say(error.message, true)));
renderBridge(null);
restoreBridge();
updateCatalogProbeButton();
for (const id of ["project-name", "root", "task", "decision", "permission"]) {
  $(id).addEventListener("input", invalidateRoutePlan);
  $(id).addEventListener("change", invalidateRoutePlan);
}
