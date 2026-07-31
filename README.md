# Codex Gate

Codex Gate는 ChatGPT식 계획과 Codex 실행을 분리하는 로컬 제어면입니다. 모델 선택, 승인 정책, 작업공간 경계, 실행 상태를 하나의 UI에서 검증하며, 기본 실행 권한은 잠겨 있습니다.

## 제공 기능

- `codex app-server --stdio`에 연결합니다.
- 설치된 Codex 버전과 생성된 JSON 스키마를 읽습니다.
- `thread/start`와 `turn/start`를 사용해 실행을 시작합니다.
- 이 릴리스에서는 Workspace Write를 잠가 둡니다.
- Read Only 실행에는 일회성 thread를 사용하고, 완료 후 `thread/unsubscribe`를 시도합니다.
- SSE로 승인 요청을 UI에 스트리밍합니다.
- 작업과 산출물을 데이터 루트 아래 SQLite에 저장합니다.
- 계정 인증 모드/플랜, 계정 전체 rate-limit 스냅샷, 일일 사용량 요약, app-server 모델 카탈로그를 읽습니다.
- Web GPT 결정과 부작용 없는 라우터 결과를 변경 불가능하고 만료되는 Route Plan으로 저장합니다.
- 유효한 Route Plan에 봉인된 최종 모델과 effort에서만 Read Only 실행을 시작합니다.
- Route Plan이 명시한 증거 범위에서 제한된 읽기 전용 Evidence Capsule을 만들며, 이 과정에서는 Codex를 시작하지 않습니다.

## 실행

```powershell
cd C:\Users\82109\Documents\Codex\2026-07-26\dl\outputs\CodexGate
python -m pip install -r requirements.txt
.\run.ps1
```

개발 중 자동 reload가 필요하면 다음을 사용합니다.

```powershell
.\run_dev.ps1
```

브라우저에서 `http://127.0.0.1:8787`을 엽니다.

## 계정과 라우터 미리보기

연결이 완료되면 Codex Gate는 다음과 같은 로컬 계정 정보만 저장합니다.

- `account/read`에서 받은 인증 모드와 플랜 유형. 이메일이 있으면 저장·표시 전에 마스킹합니다.
- 계정 전체 `account/rateLimits/read` 스냅샷(사용률과 재설정 시각 포함). 이 값은 모델별 잔여 잔액으로 해석하지 않습니다.
- `account/usage/read`의 일별 `{startDate, tokens}` 행. 집계된 사용량 상세는 저장하지 않습니다.
- `model/list`에서 받은 모델 ID, 표시 이름, 서버가 반환한 reasoning-effort 순서, 서비스 등급.

`account/rateLimits/updated`는 마지막 rate-limit 스냅샷에 sparse merge합니다. 계정 조회가 실패하거나 불완전하면 0이 아니라 항상 `UNKNOWN`으로 저장합니다. 계정 상태는 `rateLimitsByLimitId`를 포함한 모든 primary/secondary window의 최대 `usedPercent`를 사용합니다. `spendControlReached` 또는 `rateLimitReachedType`이 있으면 즉시 `BLOCKED`가 됩니다. 계산에 사용한 window와 사용률도 응답에 기록합니다. 기본 상태 임계값은 70% 미만 `NORMAL`, 70% 이상 `CONSERVE`, 90% 이상 `CRITICAL`, 100% `BLOCKED`이며 로컬 설정으로 변경할 수 있습니다. 수동 모델 상태(`AVAILABLE`, `LIMITED`, `DEPLETED`, `UNKNOWN`, `DISABLED`)는 계정 전체 제한과 별도로 유지합니다.

라우터 미리보기는 Web GPT 추천을 상한으로 받아 `model/list`가 광고한 값만 선택합니다. 알 수 없는 작업 클래스는 재분류를 위해 보류합니다. T1은 파일 두 개, T2는 다섯 개, T3은 열 개로 제한하며 더 큰 작업은 다음 클래스를 요청하며 보류합니다. 최소 effort는 T0 Medium, T1/T2 High, T3 High(파일 네 개이면 Very High), T4 Very High입니다. T5는 모델별로 정해지며 Sol은 Max, 5.5는 광고된 Ultra가 아닌 최고 effort를 사용합니다. `xhigh`, `x-high`, `very-high`, `very high`, `매우 높음`은 하나의 의미 단계로 취급하고, 최종 값은 대상 모델이 서버에서 반환한 실제 literal을 사용합니다.

낮은 위험도의 Read Only 작업만 해당 클래스의 가장 낮은 안전 모델로 하향할 수 있습니다. 낮은 위험도의 Write 작업은 테스트가 필요하며 최대 두 모델 등급까지만 이동할 수 있고, 중간/높은 위험도 작업은 자동 하향하지 않습니다. `DISABLED`, `DEPLETED`, `UNKNOWN` 모델은 자동 선택하지 않으며 `LIMITED`는 경고와 함께 가능한 후보를 따릅니다. `BLOCKED`는 모든 미리보기를 보류하고, `CRITICAL`은 T3–T5를 보류하며 Ultra를 금지합니다. `CONSERVE`는 Ultra를 금지하고 낮은 위험도의 하향 미리보기만 허용합니다. 알 수 없는 계정 상태는 사용량 기반 라우팅 없이 경고를 냅니다. Ultra는 독립 축이 세 개 이상인 Read Only 병렬 감사와 명시적 승인이 있을 때만 미리봅니다. 어떤 미리보기도 `thread/start`나 `turn/start`를 변경하지 않으며 Workspace Write와 Ultra 실행은 계속 잠겨 있습니다.

## Route Plan

Codex를 실행하기 전에 Web GPT 결정 JSON을 붙여 넣어 Route Plan을 만듭니다. `Decision`에는 작업 클래스, 추천, 파일 범위, 검증 명령, 중단 조건 외에도 `risk`, `parallel_audit`, `independent_axes`가 포함됩니다. Codex Gate는 검증된 결정 JSON을 canonicalize하고 SHA-256을 기록합니다.

`allowed_files`는 닫힌 프로젝트 상대 범위입니다. 각 항목은 정확한 파일 하나를 지정해야 합니다. 절대 경로, glob 패턴, 디렉터리, 루트 탈출, symlink/junction 탈출, 중복, canonical 범위 밖 항목은 `HOLD`를 발생시킵니다. `planned_file_count`는 검증된 고유 항목 수이며 인덱서의 프로젝트 파일 수가 아닙니다. 테스트 증거는 작업 문구에서 추론하지 않습니다. 계획은 `validation_commands_present`와 `local_test_target_exists`를 별도로 기록하며, 두 값이 함께 있을 때만 테스트 증거로 인정합니다.

`evidence_files`와 `evidence_ranges`는 canonical Decision hash에 포함되는 별도의 읽기 전용 범위입니다. `evidence_files`에는 정확한 프로젝트 상대 파일을 넣습니다. `evidence_ranges` 항목은 `{ "path": "relative/file.py", "start_line": 1, "end_line": 40 }` 형태입니다. glob, 디렉터리, 절대 경로, 루트 탈출, symlink, junction, `E:\` 경로, `E:\.codex` 경로는 Route Plan을 `HOLD`로 만듭니다. Route Plan을 만들 때 Codex Gate는 명시적으로 지정된 증거 소스의 SHA-256과 바이트 크기만 저장하며 프로젝트 트리를 열거하지 않습니다.

## Evidence Capsule

만료되지 않고 아직 claim되지 않은 `PREVIEW` 상태의 Read Only Route Plan에서만 Evidence Capsule을 만들 수 있습니다. `HOLD`, 만료, claim 완료, Workspace Write, Ultra 경로에서는 만들 수 없습니다. 앱은 `DATA_ROOT/capsules/<plan_id>/<capsule_id>` 아래에 capsule을 쓰며 `thread/start`, `turn/start`, app-server RPC를 호출하지 않습니다. Capsule에는 승인된 작업과 계획 메타데이터, 전체 텍스트 파일 또는 줄 번호가 붙은 조각만 들어갑니다. API/UI 출력에는 상태, 파일 수, 바이트 크기, 증거 fingerprint, 사유만 노출하고 소스 본문은 노출하지 않습니다.

증거 경로는 전체 파일 또는 줄 범위 중 하나만 될 수 있으며 둘 다일 수 없습니다. 전체 파일은 읽기 전에 `stat`으로 확인하고 최대 128KB여야 합니다. 범위 소스는 제한된 binary line으로 스트리밍하며 선택된 줄만 메모리에 남기는 동안 전체 SHA-256을 계산합니다. 범위 하나는 최대 250줄, 소스 하나는 최대 1,000개의 캡처 줄, 한 줄은 최대 64KB입니다. `TASK.md`, `ROUTE_PLAN.json`, `EVIDENCE_MANIFEST.json`을 포함한 전체 capsule은 최대 15개 파일, 1MB입니다. 제한을 넘으면 잘라내지 않고 `HOLD`로 처리합니다. ASCII, UTF-8, UTF-8-SIG만 허용합니다. binary 또는 지원하지 않는 인코딩은 복사하지 않으며 봉인된 메타데이터만 기록하고 결과는 `HOLD`입니다.

`EVIDENCE_MANIFEST.json`에는 각 상대 소스 경로, 캡처 모드, 소스 SHA-256, 크기, 요청된 줄 범위, capsule 경로가 기록됩니다. canonical payload와 생성 파일 hash를 합쳐 Route-Plan instance의 `capsule_hash`를 만들며, 계획 결속도 의도적으로 포함합니다. `evidence_fingerprint`는 별도로 `plan_id`를 제외하고 작업 hash, 결정 hash, 정규화된 증거 범위, 소스 SHA-256을 포함하므로 서로 다른 계획의 동등한 증거는 같은 fingerprint를 가집니다. 기존 `READY` capsule을 반환하기 전에 Codex Gate는 manifest canonical hash와 모든 생성 파일 SHA-256을 다시 계산하고, 누락/추가 파일과 link/junction을 거부하며, 재계산한 instance hash를 SQLite 값과 비교합니다. 변경·누락·변조된 capsule은 `INVALID`가 되며 새 Route Plan이 필요합니다. 자동으로 `READY`로 복구하지 않습니다. 생성된 capsule 파일은 read-only로 표시하며 로컬 저장소는 Route Plan당 활성 capsule 레코드 하나만 허용합니다.

각 immutable SQLite Route Plan에는 ID, 원래 작업 텍스트와 hash, 해석된 root, project ID, permission, decision hash, 계정 스냅샷 시각/상태, 모델 카탈로그 hash, 최종 모델/effort, 후보 사다리, HOLD 사유, 검증 증거, 정확한 예산이 기록됩니다. 기본 TTL은 10분입니다. 예산은 클래스별로 T0/T1 `tiny`, T2/T3 `standard`, T4 `complex`, T5 `critical`로 고정됩니다.

실행 입력은 정확히 한 필드 `route_plan_id`만 받습니다. root, task, project ID, permission, model, effort, budget은 봉인된 계획에서 읽으며, 추가 `model`, `effort`, `budget_level` 필드는 HTTP 422를 반환합니다. Gate 내부에서도 같은 직접 입력 형태를 거부하므로 legacy 실행 adapter가 없습니다.

실행 가능한 계획은 `PREVIEW`, Read Only, non-Ultra뿐입니다. SQLite transaction으로 계획을 원자적으로 claim한 뒤 `claimed → started → failed|completed`를 기록합니다. 시작 실패도 소비된 상태로 남으며 새 계획이 필요합니다. 부분 시작 시 interruption 또는 unsubscribe를 시도합니다. 누락, 만료, 수정, 사용 완료, HOLD 계획은 거부하고 계정과 선택 모델도 다시 확인합니다. 계정 상태가 악화되었거나 최종 모델이 `DEPLETED`, `UNKNOWN`, `DISABLED`가 되면 계획을 무효화합니다. `thread/start`와 `turn/start`에는 계획의 최종 route만 전달합니다. 결과에는 `route_plan_id`, `decision_hash`, 요청/실제 모델, reroute 사유가 남습니다. `model/rerouted`는 기록하고 `thread/compacted`는 즉시 turn을 중단합니다. 80% token 경고는 실행당 한 번만 냅니다.

인증 정보나 이메일을 쓰지 않고 가려진 계정/모델 요약을 출력하려면 다음을 사용합니다.

```powershell
python scripts\probe_account.py
```

## 데이터 루트

앱은 로컬 상태를 `CODEX_GATE_HOME` 아래에 저장합니다.

- 기본값: `C:\Users\<you>\CodexGate`
- 재정의: `CODEX_GATE_HOME`

## 금지된 루트

preflight와 실행 전에 금지 루트에 대한 작업공간 접근을 차단합니다.

- 기본 금지 루트: `E:\.codex`
- 작업공간이 금지 루트 그 자체이거나 그 안/부모이면 거부합니다(예: `E:\`).
- `CODEX_GATE_FORBIDDEN_ROOTS`로 재정의하거나 더 추가할 수 있습니다.

금지 루트를 가리키는 작업 텍스트, 결정 payload, 승인 요청의 command/path 데이터는 거부되며 명확한 중단 사유와 함께 기록됩니다.

## 보안 메모

## Read 격리 게이트

Read Only live 실행 전에 **Test Read Only isolation**을 사용해야 합니다. Probe는 `DATA_ROOT/isolation-probes` 아래에서만 무작위 canary 두 개를 만듭니다. 하나는 capsule 디렉터리 안에, 하나는 바깥의 sibling에 둡니다. 임시 app-server 연결은 생성된 스키마의 `readOnly` sandbox 정책, capsule `cwd`, 10초 `timeoutMs`, 동일한 asyncio timeout으로 독립 `command/exec` 요청 두 개만 수행합니다. Windows에서는 의도적으로 `outputBytesCap`과 `disableOutputCap`을 생략하고 서버 기본 cap을 사용합니다. `thread/start`나 `turn/start`를 호출하지 않으므로 model turn이나 model token을 소비하지 않습니다.

고정 command는 `sys.executable -I -S -c ...`이며 ASCII marker 하나만 출력합니다: `READ_OK`, `READ_DENIED`, `READ_ERROR`. 출력은 `splitlines()`로 정규화하고 1KB보다 큰 응답은 `ERROR`로 처리합니다. 바깥에서 `READ_OK`가 나오면 `UNSAFE_FULL_DISK_READ`입니다. 안쪽 `READ_OK`와 바깥쪽 명시적 `READ_DENIED`가 함께 있을 때만 `SAFE_CANDIDATE`가 됩니다. 일반 실패, timeout, 빈 출력, `READ_ERROR`는 안전한 것으로 보지 않고 모두 `ERROR`입니다. 이 릴리스는 새 `SAFE_CAPSULE_ONLY` 결과를 발행하지 않으며 `SAFE_CANDIDATE`도 live 실행을 열지 않습니다. 저장된 `ERROR`, `UNSAFE_FULL_DISK_READ`, `UNKNOWN`은 즉시 차단합니다. DB에는 상태, 시각, Codex 버전, 생성 스키마 SHA-256, canary SHA-256, 정제된 결과 코드만 저장하며 canary 내용, 경로, command, raw stdout/stderr는 저장하지 않습니다. 결과는 24시간 후 만료되고 설치된 버전 또는 스키마가 바뀌면 안전 계열 결과가 `UNKNOWN`이 됩니다. UI에는 격리 상태와 바깥 읽기가 성공했는지 명시적으로 거부됐는지만 표시하며, 이 릴리스의 live 실행 버튼은 계속 잠겨 있습니다.

### WSL2 + bubblewrap preflight

선택적 `WSL2_BWRAP` backend는 별도의 fail-closed preflight입니다. 사용자가 WSL 배포판 이름 하나를 직접 입력하고 저장해야 하며 Codex Gate는 배포판, `bwrap`, Python, Codex를 선택·설치·구성하지 않습니다. 먼저 WSL2와 선택한 배포판에 대해 고정 `HOST_CHECK`(`wsl.exe --list --verbose`)을 수행하고, 이어서 고정 `DISTRO_QUERY`(`wsl.exe -d <selected> --exec /usr/bin/python3 -I -S -c <embedded code>`) 하나를 실행합니다. embedded code는 배포판/Python 메타데이터를 읽고 3초 timeout으로 `/usr/bin/bwrap --version`만 호출합니다. HOST_CHECK 제한은 10초, DISTRO_QUERY는 WSL cold start를 고려해 30초입니다. 각각 최대 8KB만 수집하고 정제된 stage code와 timing만 기록합니다. 알 수 없는 키, 추가 줄, 유효하지 않은 UTF-8이 있는 canonical one-line JSON 응답은 거부합니다. 성공한 preflight 메타데이터에는 5분 별도 cache를 사용하며 30분 canary cache와 분리합니다. 사용자 설정만 반영한 `config_hash`는 canonical `tool_fingerprint`와 별도로 저장합니다. `tool_fingerprint`에는 WSL2, 배포판 ID/버전, Python, bwrap 존재/버전, probe 버전이 포함되며 cache key는 세 값을 모두 결합합니다. raw stdout/stderr와 절대 경로는 저장하거나 표시하지 않습니다.

고정 canary에서는 Windows Capsule 디렉터리만 `wslpath`로 번역해 `/work`에 read-only bind합니다. bubblewrap은 `--unshare-all`, 별도 network namespace, read-only runtime bind(`/usr`, `/bin`, `/lib`, `/lib64`, `/etc`), tmpfs `/tmp`를 사용합니다. `/mnt`, Windows 사용자 폴더, Catalog Source Root는 bind하지 않습니다. canary는 `/work`를 읽고, 외부/host-mount 대상 읽기와 Capsule 쓰기를 실패시키며, `/tmp`에는 쓰고 삭제하고, 로컬 loopback listener에는 도달하지 못해야 합니다. 중복/예상 밖 marker, 일반 실패, timeout, 출력 초과는 `ERROR`입니다. 보이는 host read, write, network 접근은 각각 `UNSAFE_HOST_FS`, `UNSAFE_WRITE`, `UNSAFE_NETWORK`이 됩니다. 통과 결과는 `SAFE_CANDIDATE`일 뿐이며 같은 configuration과 tool fingerprint에 대해 30분 cache하고 **여전히 live 실행을 열지 않습니다**. Token Ledger는 preflight count/time과 canary count/time을 분리하고 token과 app-server RPC는 0으로 둡니다. UI에는 상태, 정제된 오류 코드, 환경이 cache 결과를 무효화했는지만 표시하며 tool version 문자열은 노출하지 않습니다.

### 봉인된 WSL Codex Runtime, Phase 0

Phase 0은 WSL-native Codex runtime을 준비하지만 시작하지는 않습니다. 사용자가 `/usr/local/bin/codex` 또는 `/home/<user>/.local/bin/codex` 아래의 정확한 binary 경로 하나를 선택해야 합니다. discovery, `PATH` fallback, installer, 자동 버전/스키마 업데이트는 없습니다. 고정 direct-argv preflight는 regular file인지, symlink가 아닌지, executable mode인지, binary SHA-256, `codex --version`만 확인합니다. 정확히 `codex-cli 0.145.0`만 허용합니다. 디렉터리, symlink, non-executable, malformed, 버전 불일치 선택은 fail-closed로 처리합니다. 선택한 경로는 로컬 설정에만 남고 API나 UI로 반환하지 않습니다.

향후 실행을 위해 앱은 immutable private bubblewrap launch spec과 그 hash를 계산합니다. 제공된 Capsule을 `/work`에 read-only로 bind하고 working directory를 `/work`로 고정하며 read-only runtime bind만 사용하고 tmpfs `/tmp`, `/runtime-state`, 새 `/home/codex`를 제공합니다. 상속된 Windows/WSL 환경값을 지우고 고정 `PATH`, `HOME`, `TMPDIR`, `LANG`만 허용합니다. `/mnt`, Windows 사용자 폴더, Catalog Source Root, data root는 spec에 없으며 network는 공유하지 않습니다. runtime fingerprint에는 binary digest, 고정 버전, WSL isolation cache key, runtime policy version이 포함됩니다. credential, API key, argv, environment 값, 절대 binary 경로는 노출하지 않습니다.

Phase 0은 의도적으로 봉인된 authentication이나 model egress 설계가 없으므로, 검증을 통과한 binary는 `EGRESS_UNCONFIGURED`와 내부 `READY_CANDIDATE` preflight 신호로 기록합니다. 허용되는 Codex 호출은 고정 `--version` 메타데이터 확인뿐입니다. `app-server`, login, account, model turn을 시작하지 않으며 Windows app-server 경로, Workspace Write, Ultra, live 실행을 열지 않습니다. Token Ledger에는 로컬 runtime-preflight count와 duration만 기록하고 token과 app-server RPC는 0으로 유지합니다.

Runtime identity payload는 `runtime-identity-v1`을 사용합니다. 성공한 `EGRESS_UNCONFIGURED` 행에는 binary SHA-256, runtime fingerprint, launch-spec hash, 현재 isolation cache key, fail-closed flag가 있어야 합니다. 필드가 빠진 과거 행은 읽기 전용 `BLOCKED/runtime_identity_incomplete`로 처리하며 앱은 digest를 추측하거나 backfill하지 않습니다. 이후 공식 preflight만 legacy 행을 complete identity로 원자적으로 교체할 수 있고 API/UI snapshot에는 binary path, argv, environment, raw preflight 출력이 여전히 나오지 않습니다.

### 봉인된 Egress Contract Phase 1

Phase 1은 immutable local-only 미래 egress contract를 만들지만 relay, broker, socket listener, Codex process, DNS lookup, network request를 시작하지 않습니다. 유일한 provider는 `codexgate-sealed`입니다. ephemeral `CODEX_HOME/config.toml` bytes에 `wire_api = "responses"`, `requires_openai_auth = false`, `env_key = "CODEXGATE_EPHEMERAL_TOKEN"`, WebSocket 없음, request/stream retry 0을 설정합니다. config bytes는 저장하지 않으며 SQLite에는 SHA-256과 허용 필드의 닫힌 snapshot만 남깁니다. 내장 `openai`, `openai_base_url`, proxy environment 변수는 이 경로에 포함하지 않습니다.

Contract는 sandbox 내부에서 정확히 `http://127.0.0.1:8788/v1`만 허용하고 broker에는 미래의 Unix-socket 경계 하나만 둡니다. relay에는 DNS, internet, 대체 socket 출력이 없습니다. 미래 broker는 `POST /v1/responses`만 허용하고 request 256KB, response 2MB, timeout 120초를 강제합니다. CONNECT, redirect, absolute-form target, 임의 `Host` 값은 거부하고 호출자의 `Authorization`, `Cookie`, `Proxy-*` header는 제거합니다. 향후 broker가 contract 바깥에서 인증을 주입할 수 있지만 여기에는 token, credential, raw request, raw response를 저장하거나 로그하지 않습니다.

Contract hash는 runtime fingerprint, WSL isolation cache key, binary SHA-256, provider-config SHA-256, contract policy version에 결속됩니다. 결속이 바뀌면 사용할 수 없습니다. relay, broker, authentication이 의도적으로 없으므로 저장되는 최종 상태는 `AUTH_UNCONFIGURED`이며 runtime start, live 실행, Workspace Write, Ultra는 계속 잠겨 있습니다. Token Ledger에는 로컬 contract construction count와 duration만 기록하고 token과 app-server RPC는 0으로 유지합니다.

### 봉인된 Egress Local Harness Phase 2

명시적인 contract 생성은 immutable SQLite instance 하나를 저장합니다. preview hash는 저장된 contract hash와 같아야 하며, 동일한 runtime, isolation, binary, provider, policy identity 요청은 중복을 만들지 않고 기존 instance를 반환합니다. Harness는 이 instance에 결속되고 현재 runtime fingerprint, isolation key, contract hash가 일치할 때만 `READY`입니다.

Phase 2는 결정적인 **fake runner만** 제공합니다. bubblewrap-local `127.0.0.1:8788` relay가 정확히 하나의 `POST /v1/responses` 요청을 하나의 AF_UNIX broker 경계로 전달하는 상황을 모델링합니다. broker는 `Authorization`, `Cookie`, `Proxy-*`를 제거하고 CONNECT, absolute-form target, redirect, 다른 host/method/path를 거부하며 봉인된 256KB request, 2MB response, 120초 contract 제한을 강제합니다. fake Responses 형태 결과는 canonical deterministic hash를 갖습니다. 실제 Unix socket, loopback listener, WSL process, bwrap process, Codex process, DNS lookup, 외부 연결은 전혀 열지 않습니다.

모델 launch 정책은 environment를 지우고 고정 `PATH`, `HOME`, `TMPDIR`, `LANG`만 허용합니다. 실행별 private socket-directory placeholder만 사용하며 `/mnt`, Windows 경로, Source Root, data root를 bind하지 않습니다. Harness summary에는 상태, request/response 크기, response hash, counter, duration, 정제된 오류만 남기고 body, credential, argv, socket path, raw output은 남기지 않습니다. 시작 시 orphaned `RUNNING` summary를 `ERROR/harness_interrupted`로 바꾸며 동일한 동시 요청은 single-flight합니다. fake harness가 통과해도 `AUTH_UNCONFIGURED`는 바뀌지 않고 Runtime start, 일반 live 실행, Workspace Write, Ultra는 계속 잠깁니다.

### 봉인된 Egress Local Harness Phase 3

Phase 3은 고정 argv WSL supervisor runner를 추가하지만 선택하지는 않습니다. launch 직전 preview hash, runtime fingerprint, isolation cache key, binary digest, provider configuration digest, Ubuntu 선택이 현재 immutable Contract instance와 일치해야 합니다. preview object만으로는 차단합니다. supervisor는 `wsl.exe -d Ubuntu --exec /usr/bin/python3 -I -S -u -c`로 한 번 호출되는 고정 Python bytes이며 사용자 command, path, environment, request body, credential, proxy setting을 받지 않습니다.

준비된 topology에는 `bwrap --unshare-all --clearenv` 두 개가 있습니다. 하나는 private socket 하나만 가진 AF_UNIX-only broker이고, 다른 하나는 그 socket directory를 read-only로, 작은 `/work` fixture를 read-only로, sandbox-local `127.0.0.1:8788` listener 하나만 가진 relay/client sandbox입니다. 둘 다 tmpfs HOME과 `/tmp`를 사용하며 `/mnt`, Windows 경로, Source Root, data root, user HOME은 없습니다. client는 `POST /v1/responses` 하나만 허용합니다. 두 번째 연결, 추가 frame, broker의 민감 header, non-loopback host, 다른 path/method, redirect, absolute-form target은 정책 위반입니다.

Supervisor는 크기, hash, counter, 정제 상태만 담은 base64url canonical result frame 하나를 반환합니다. stdout과 stderr는 분리하고 합산 8KB로 제한합니다. startup, request, total 제한은 각각 10초, 15초, 30초입니다. runner는 두 process tree를 종료하고 socket, fixture, temporary directory가 정리된 경우에만 통과시킵니다. Phase 3 테스트는 fake WSL supervisor만 사용합니다. WSL, bubblewrap, AF_UNIX, network, Codex, app-server, model process를 실행하지 않으며 `AUTH_UNCONFIGURED`, Runtime start 차단, Workspace Write, Ultra, 일반 live-run 잠금은 그대로입니다.

### Actual WSL Harness Gate Phase 3.1

이제 immutable Contract는 현재 `SAFE_CANDIDATE` Canary에 Harness 예상 duration 30초와 5분을 더한 시간이 남아 있을 때만 만들 수 있습니다. 앱은 현재 `config_hash`, `tool_fingerprint`, 고정 Repro protocol version에서 Repro key를 계산하며 이 key는 Isolation cache key와 의도적으로 다릅니다. 일치하는 Repro 행은 동일한 environment hash와 유효한 result hash를 가지고 `SAFE_REPRODUCIBLE` 및 requested/completed/successful 10/10/10이어야 합니다. Contract identity는 Repro version, 계산된 key, result hash에 결속되고 실제 runner는 미래 launch 직전에 이를 모두 다시 확인합니다.

Fake와 actual 결과는 `contract_hash + runner_kind + runner_version`으로 분리된 SQLite identity를 사용합니다. 따라서 `FAKE PASSED`는 `WSL PASSED`로 재사용할 수 없으며 runner version 변경은 별도 결과를 만듭니다. 기존 fake endpoint는 `/api/isolation/wsl/egress-harness`입니다. actual endpoint는 분리되어 있고 로컬에서 생성한 일회용 arm nonce가 필요합니다. nonce 평문은 저장하지 않으며 contract와 runner에 결속하고 5분 후 만료시키며 재사용할 수 없습니다. Phase 3.1에서는 이 endpoint를 계속 hard-disabled로 유지했고 Phase 3.3에서 아래에 문서화한 더 엄격한 2분 execution-window protocol로 대체합니다. 로컬 API 예시는 `http://127.0.0.1:8787`만 사용하며 `testserver`, `0.0.0.0`, 외부 host는 계속 거부합니다. authentication, network egress, SAFE_CAPSULE_ONLY, Runtime start, live 실행, Workspace Write, Ultra는 모두 잠겨 있습니다.

### Actual WSL Harness Implementation Seal Phase 3.2

WSL runner는 실행과 검토에 하나의 구현 원천을 사용합니다. 공통 bubblewrap argument, broker, relay/client, supervisor argv template을 공유합니다. child launch spec과 고정 supervisor는 실제 `/usr/bin/python3 -I -S -u -c <fixed code>` 형식을 포함해 이 template을 그대로 materialize합니다. supervisor code, broker child code, relay child code, canonical argv-template set의 SHA-256을 계산하고 canonical aggregate를 `runner_implementation_hash`로 사용합니다. WSL runner version은 이 hash에서 파생됩니다. code나 argv가 한 바이트라도 바뀌면 새 runner version과 implementation identity가 생깁니다.

Harness 저장과 arm 결속은 `contract_hash + runner_kind + runner_version + runner_implementation_hash`를 사용합니다. migration은 legacy fake 행에 보존된 fake implementation hash를 부여하고, seal이 없던 구 WSL 행에는 fail-closed zero hash를 부여합니다. 따라서 과거 WSL `PASSED` 결과나 arm은 현재 runner를 만족할 수 없습니다. 엄격한 result frame에는 전체 implementation hash가 들어가며 불일치는 `POLICY_VIOLATION`입니다.

Socket 증거는 오해를 부르는 전체 `tcp=0`이 아니라 역할별로 기록합니다. broker는 pathname AF_UNIX listener 하나만 허용하고 INET, UDP, DNS 시도는 0이어야 합니다. relay/client는 broker AF_UNIX connection 하나와 `127.0.0.1` TCP listener/connection 쌍 하나만 허용합니다. non-loopback, UDP, DNS 시도는 0이어야 합니다. Host, method, path, 민감 header 제거, canonical frame, 크기, timeout, cleanup 검사는 그대로입니다. 이 단계도 fake process runner만 사용하며 WSL, bwrap, AF_UNIX, network, Codex, app-server, model turn을 실행하지 않습니다.

### Actual WSL Harness Execution Window Phase 3.3

Phase 3.3에는 persistent enable flag가 없습니다. 기본 상태는 `DISABLED`이며, `127.0.0.1`에서 동일한 local `Origin`으로 들어온 버튼 요청만 `ARMED` execution window를 열 수 있습니다. window는 정확히 2분 동안만 유효하고 연장할 수 없으며 응답에서만 두 개의 평문 일회용 nonce를 반환합니다. SQLite에는 SHA-256 digest만 저장합니다. 재시작 시 남아 있는 `ARMED` 레코드는 `EXPIRED`가 됩니다.

Window는 immutable Contract ID/hash, WSL runner kind/version/implementation hash, 현재 isolation config/tool/cache identity, 현재 10/10/10 `SAFE_REPRODUCIBLE` Repro version/key/result hash에 결속됩니다. arm 시 Canary가 최소 5분 이상 남아 있어야 하고 완전한 Repro 증명이 있어야 하며, actual runner를 선택하기 직전에도 다시 확인합니다. 결속이 바뀌면 window를 소비하고 요청을 차단합니다. 실행 endpoint는 새 window nonce와 기존 arm nonce를 모두 요구하며 runner 호출 전에 두 capability를 원자적으로 소비하므로 retry로 재사용할 수 없습니다.

이 endpoint는 봉인된 `WSLEgressHarnessRunner` identity만 허용합니다. fake identity는 정책 위반이며 actual evidence가 될 수 없습니다. Window는 Runtime, `SAFE_CAPSULE_ONLY`, 일반 live-run, Workspace Write, Ultra, network, authentication 권한을 열지 않습니다. 구현은 no-I/O process double로 테스트하며 WSL, bubblewrap, AF_UNIX, Codex, app-server, model turn을 실행하지 않습니다.

### 봉인된 Offline Codex Process Canary Phase 4.0

Phase 4.0은 별도의 2분, 1회용 offline Codex Canary window를 정의합니다. 완전한 `runtime-identity-v1`, 현재 immutable `AUTH_UNCONFIGURED` Contract, 정확히 현재 결속의 `WSL_SUPERVISOR` Harness `PASSED`, fresh isolation Canary, 일치하는 `SAFE_REPRODUCIBLE` 10/10/10 결과가 필요합니다. Canary runner implementation hash는 고정 broker, relay/Codex, supervisor program bytes, 고정 Codex argv, 고정 prompt, deterministic fake Responses 결과를 canonical하게 결속합니다. 이 입력 중 하나라도 바뀌면 다른 runner identity가 되어 이전 `PASSED` 결과나 capability를 재사용할 수 없습니다.

모델 process 배치는 read-only broker bubblewrap 하나와 봉인된 relay/Codex bubblewrap 하나입니다. 후자는 immutable Contract TOML bytes만 config로 가지는 throwaway tmpfs `CODEX_HOME`, 고정 `/work`, 상속 environment·host mount·credential·일반 network가 없는 환경을 사용합니다. 고정 `POST /v1/responses` 하나만 허용하며 WebSocket, 두 번째 request, model 변경, tool call, command 실행, file change, retry, reroute, network tool을 금지합니다. 유효 결과는 정확한 success marker, exit code 0, 45초 제한, 합산 최대 16KB output을 요구합니다. raw prompt, response, config, stdout, stderr, path, token 값은 저장하지 않습니다.

이 단계의 production runner는 의도적으로 `DISABLED`입니다. 따라서 arm/run API는 fail-closed이고 WSL, bubblewrap, Codex, socket, 외부 network, app-server RPC, model request를 시작할 수 없습니다. 테스트는 in-memory deterministic runner만 사용합니다. 계획/fake 이벤트는 `LOCAL_ESTIMATE`/`ESTIMATED`를 사용하고, 미래의 실제 runner만 `LOCAL_OBSERVED`/`OBSERVED` process count와 monotonic duration을 기록할 수 있습니다. provider token column은 null이고 external token과 RPC는 0이며 보고 상태는 `NOT_COMPARABLE`입니다. 계획 process count는 측정 합계에 넣지 않습니다. 향후 Canary가 성공해도 Runtime start, 일반 live 실행, `SAFE_CAPSULE_ONLY`, Workspace Write, Ultra는 잠긴 채로 남습니다.

Phase 4.1은 durable enable switch 없이 별도의 **Offline Canary Execution Permit**을 추가합니다. 기본 상태는 `DISABLED`이며 동일한 local `Origin`의 `127.0.0.1` 요청만 2분짜리 Permit 하나를 발급할 수 있습니다. SQLite에는 Permit nonce SHA-256만 저장합니다. Permit은 완전한 `runtime-identity-v1`, immutable Contract ID/hash, 정확한 actual Harness `PASSED` identity, fresh Canary와 일치하는 `SAFE_REPRODUCIBLE` 10/10/10 proof, 봉인된 Offline Canary runner implementation hash에 결속됩니다. 유효한 Permit은 기존 Canary window 하나를 arm할 수 있지만 runner를 전역적으로 enable하지는 않습니다.

실행 request는 binding을 다시 확인하거나 runner를 선택하기 전에 Permit nonce와 Canary-window nonce를 한 transaction에서 원자적으로 소비합니다. binding이 바뀌면 `execution_binding_changed`로 기록하고 어느 capability도 재시도할 수 없습니다. 앱이 재시작되면 남은 Permit은 만료됩니다. 구체적인 봉인 WSL Canary runner identity만 허용하며 fake runner 주입은 정책 위반입니다. Permit 발급과 소비는 process를 시작하지 않습니다. pre-spawn 차단은 `LOCAL_OBSERVED` `local_processes = 0`, null provider token, external model request 0, app-server RPC 0으로 기록합니다. 현재 봉인된 production runner는 계속 disabled이므로 이 단계에서도 WSL, bwrap, Codex, socket, DNS, model 실행은 없습니다.

### 봉인된 Offline Codex Canary One-Shot Runner Phase 4.2

Phase 4.2는 일반 Canary endpoint를 계속 `codex_canary_execution_disabled`로 fail-closed합니다. 별도의 local IPv4/same-Origin one-shot endpoint만 구체적인 `WSLCodexProcessCanaryRunner`를 선택할 수 있습니다. 사용자 command, path, model, prompt, argv는 받지 않습니다. Permit과 Canary-window nonce hash, 완전한 Runtime, Contract, actual Harness, Canary, Repro, runner implementation identity를 하나의 SQLite `BEGIN IMMEDIATE` transaction에서 다시 검증하고 원자적으로 claim합니다. claim에는 identifier와 SHA-256 값만 저장하며 두 평문 nonce는 즉시 복구할 수 없게 됩니다.

claim이 `RUNNING`에 도달하기 전에는 runner object나 executor를 materialize하지 않습니다. 구체 runner는 봉인된 launch specification만 받고 spawn을 최대 한 번 시도할 수 있습니다. retry, fallback, reroute, resume, 두 번째 spawn은 금지합니다. binding 변경은 process가 시작되기 전에 capability를 소비하고 `execution_binding_changed`로 보고합니다. 재시작 복구는 orphaned `CLAIMED`/`RUNNING` claim을 `ERROR/canary_interrupted`로 바꿉니다. Phase 4.2 production factory에는 의도적으로 executor가 없으므로 one-shot endpoint는 WSL/Codex를 시작하는 대신 zero-process observed block을 기록합니다. 테스트는 동일한 concrete runner class 뒤에 deterministic no-I/O executor만 주입합니다. 미래의 실제 spawn은 실제 시작 수와 monotonic duration만 `LOCAL_OBSERVED`로 기록하고 provider token은 null, fake usage는 무시하며 external-model과 app-server-RPC counter는 0으로 둡니다.

### 봉인된 Offline Codex Canary Production Executor Phase 4.3

Phase 4.3은 없던 factory 구현을 새 sealed WSL supervisor executor로 대체하지만, immutable one-shot claim이 `RUNNING`으로 바뀐 뒤에만 접근할 수 있습니다. factory는 claim UUID만 받고 singleton, fallback executor, user argv, prompt, model, path, environment input은 받지 않습니다. executor는 fixed argv를 계산하기 전에 Runtime identity, immutable Contract, actual Harness proof, fresh Canary/Repro binding, runner seal을 다시 확인합니다. binding이나 implementation seal이 바뀌면 supervisor가 시작되기 전에 차단합니다.

검토 spec과 supervisor는 공통 broker, relay/Codex, WSL argv template을 사용합니다. 두 bubblewrap child는 `--unshare-all`과 `--clearenv`를 사용합니다. `/work`에는 고정 read-only fixture만 있고 CODEX_HOME, HOME, `/tmp`, runtime state는 실행별 private tmpfs입니다. `/mnt`, Windows 경로, Source Root, DATA_ROOT, user HOME은 없습니다. ephemeral token은 실행 process 안에서만 만들고 저장하거나 로그하지 않습니다. 최초 실제 supervisor spawn은 `spawn_count=1`을 원자적으로 기록합니다. timeout, output/frame/cleanup 실패 또는 잔여 resource가 있으면 sanitized frame은 fail-closed입니다. Ledger event는 supervisor, bubblewrap, Codex count를 구분하고 관측된 local metric만 사용하며 provider token은 null, external request와 app-server RPC는 0으로 유지합니다. 이 단계 테스트는 no-I/O supervisor double만 사용하고 Runtime start와 모든 일반 live permission은 잠겨 있습니다.

HTTP 보안 기본값은 다음과 같습니다.

- `Host`는 `127.0.0.1`과 `localhost`만 허용합니다.
- `Origin`이 있으면 같은 local origin과 일치해야 합니다.
- `project_id`는 안전한 slug 또는 UUID여야 합니다.
- Artifact 이름은 내부 allowlist로 제한합니다.
- Workspace Write는 이후 릴리스에서 write-validation 단계가 명시적으로 활성화될 때까지 잠겨 있습니다.

## 수동 Web GPT Bridge

Web GPT Bridge는 의도적으로 반수동입니다. Codex Gate는 ChatGPT 페이지를 제어하거나, web에 packet을 보내거나, clipboard를 감시하거나, web response를 자동으로 수집하지 않습니다. Bridge 작업당 하나의 visible action만 활성화됩니다: architecture packet 복사, architecture response import, review packet 준비/복사, review response import, terminal state 재시작. 복사는 사용자가 클릭한 뒤 `navigator.clipboard.writeText`를 사용하며 복사가 성공한 후에만 선택적인 작업별 ChatGPT URL을 엽니다. Clipboard 읽기는 사용자가 import action을 누른 뒤에만 수행하고 `readText`가 실패하면 수동 paste field를 표시합니다.

Packet은 하나의 marker block입니다. `BEGIN`, JSON object body 하나, `END` 순서입니다. request envelope와 response envelope는 의도적으로 다릅니다. Request에는 `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `CREATED_AT`, `EXPIRES_AT`, `SCHEMA_VERSION`, `BODY`, 로컬에서 계산한 `REQUEST_SHA256`이 들어갑니다. Response에는 `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `SCHEMA_VERSION`, `BODY`만 필요합니다. 최대 packet 크기는 60KB입니다. nonce는 1회용이며 task, phase, type, nonce, 필수 field가 모두 일치해야 합니다. 알 수 없는 response field, marker 누락, 잘린 packet, 여러 marker block은 거부합니다.

나가는 `ARCHITECT_REQUEST` packet에는 로컬 task, 제약, 질문만 담으며 project root, repository body, game source, 전체 log, secret은 담지 않습니다. secret처럼 보이는 값과 절대 사용자 경로가 있으면 복사 전에 Bridge task를 `HOLD`로 둡니다. `ARCHITECT_RESPONSE`는 `execute`(기존 local Route Plan creator 호출) 또는 `need_more_evidence`(요청된 evidence 이름만 표시하고 새 architecture nonce 생성) 중 하나입니다. HOLD Route Plan은 Codex 실행을 enable하지 않습니다.

`REVIEW_REQUEST`는 Route Plan이 준비되고 사용자가 실제 결과와 local-validation summary를 제공한 뒤에만 만들 수 있습니다. `REVIEW_RESPONSE`는 `SUCCESS`, `HOLD`, `RETRY`, `REDESIGN`, `ROLLBACK`만 허용합니다. `RETRY`는 새 nonce와 함께 새 architecture cycle을 시작하며 Route Plan이나 Codex thread를 재사용하지 않습니다. `REDESIGN`과 `ROLLBACK`은 재시작 전까지 명시적인 terminal state로 남습니다. Bridge DB에는 copy/receive timestamp와 response hash만 저장하고 clipboard text나 Web GPT response text는 저장하지 않습니다. Packet preview/import는 app-server RPC를 호출하지 않습니다.

### Protocol v2

Bridge request는 schema version `2.0`을 사용합니다. request를 만들 때 Codex Gate가 `CREATED_AT`과 `EXPIRES_AT`(30분)을 고정하고 로컬에서 계산한 `REQUEST_SHA256`을 포함합니다. 같은 대기 request를 다시 복사하거나 열면 동일한 packet과 hash를 반환합니다. Web GPT response는 의도적으로 `TYPE`, `TASK_ID`, `PHASE`, `NONCE`, `SCHEMA_VERSION`, `BODY`만 요구하며, Codex Gate가 받은 response를 자체 canonicalize하고 결과 hash만 저장합니다.

모든 v2 request에는 `execute`와 `need_more_evidence` architecture body, 모든 review verdict 예시를 포함하는 정확한 `RESPONSE_CONTRACT`가 들어갑니다. parser는 붙여 넣은 text에서 marker block 하나만 추출하므로 Markdown code fence 하나와 주변 설명은 허용합니다. marker block 누락, 절단, 중복은 계속 거부하며 알 수 없는 response field와 task/phase/nonce 불일치도 거부합니다.

response envelope, task, phase, nonce, expiry, 검증된 BODY는 nonce를 claim하기 전에 확인합니다. secret처럼 보이는 값이나 절대 사용자 경로 같은 안전하지 않은 BODY는 claim 전에 거부하므로 같은 nonce로 고쳐 다시 붙여 넣을 수 있습니다. response 처리 중에는 task가 `PROCESSING_RESPONSE`가 되고 import action을 비활성화합니다. 같은 response hash의 재생은 idempotent이고 bridge idempotency key가 중복 Route Plan을 막습니다. 만료 후 response가 도착하면 task와 nonce를 `expired_response`와 함께 원자적으로 `HOLD`로 옮깁니다. plan 생성이 실패하면 nonce를 failed로 표시하고 task를 `HOLD`로 옮깁니다. `RETRY`는 다음 architecture packet을 위해 정제된 review verdict/notes를 보존하면서 오래된 requested evidence를 지우고, `REDESIGN`은 다음 재시작을 위해 review feedback을 보존합니다.

`need_more_evidence`는 이제 정확히 `type`, `label`, `reason`, `required`, `target_hint`만 가진 구조화 request를 최대 20개 저장합니다. 지원 type은 `file_metadata`, `fast_fingerprint`, `text_range`, `log_excerpt`, `json_structure`이며 `target_hint`는 설명용일 뿐입니다. 사용자는 각 request를 정확한 프로젝트 상대 source file 하나에 매핑해야 합니다. 절대 경로, glob, 디렉터리, traversal, symlink/junction 탈출, `E:\`, `E:\.codex`, `.env`, key, certificate, credential, service account 같은 민감한 이름은 거부합니다. `file_metadata`는 stat data만 읽습니다. `fast_fingerprint`는 20GB 파일이어도 첫 1MB와 마지막 1MB만 읽습니다. text range는 250줄(파일당 1,000줄), log excerpt는 200줄로 제한합니다. JSON 출력에는 구조 key, type, array length만 넣고 scalar 값은 넣지 않습니다. binary source는 metadata/fingerprint만 허용합니다.

Evidence request와 정제된 결과 metadata는 `REQUESTED → MAPPED → COLLECTING → READY` 또는 `FAILED`/`REJECTED` 상태로 로컬에 저장합니다. source result는 32KB, 전체 web evidence는 50KB로 제한합니다. secret처럼 보이는 text, authorization material, DB URL, 절대 사용자 경로는 masking하지 않고 실패시킵니다. 출력되는 모든 source path는 `PROJECT_ROOT/<relative>` 형식입니다. 필수 request가 모두 `READY`가 되면 Bridge는 새 architecture nonce를 만들고 수집 결과, 결정적 hash, collector version을 다음 `ARCHITECT_REQUEST`에 넣습니다. 따라서 이 값도 `REQUEST_SHA256`에 포함됩니다. 선택 항목 실패는 warning으로 남습니다. collection과 packet construction 어느 쪽도 app-server RPC, shell command, Codex turn을 호출하지 않습니다.

Read Only task만 Bridge를 시작할 수 있고 작업공간 root는 다른 곳과 같은 forbidden-root 정책으로 검증합니다. 앱은 최근 미완료 task를 노출하고 page load 시 최신 task를 복원합니다. 대기 task는 원래 request packet을 review용으로 보존합니다. 시작 복구는 이전 process의 stale `PROCESSING_RESPONSE` task를 정확히 한 번 처리해 `HOLD`로 옮깁니다. snapshot/get/recent 같은 일반 read는 Bridge state를 변경하지 않습니다. pending v1 record는 자동 변환하지 않고 restart-required로 표시합니다. 이 Bridge 작업은 local-only이며 `thread/start`, `turn/start`, Workspace Write, Ultra, live Codex run을 호출하지 않습니다.

## Asset Catalog, Phase 1

Asset Catalog Phase 1은 명시적으로 등록한 Source Root에 대한 로컬 metadata-only inventory입니다. source에는 내부 UUID와 사용자용 alias가 부여됩니다. 절대 root는 SQLite에만 저장하고 HTTP API, UI, log, Bridge packet으로 반환하지 않습니다. 등록에는 존재하는 절대 디렉터리가 필요하며 forbidden-root 관계(`E:\`, `E:\.codex`, 부모, 하위), symlink, junction, 기타 reparse point를 거부합니다.

Scan은 `follow_symlinks=False`인 반복 `os.scandir`를 사용합니다. project-relative path, case-folded path key, extension, size, `mtime_ns`, filesystem ID, extension에서 유도한 asset kind, scan generation, Phase-1 `QUEUED` fingerprint marker만 기록합니다. source file을 열거나 full-file SHA-256을 계산하거나 AssetBundle/FBX/PMX/texture를 검사하거나 shell command, app-server RPC, `thread/start`, `turn/start`를 호출하지 않습니다. `bytes_indexed`는 metadata size의 합이고 `content_bytes_read`는 계속 0입니다.

첫 scan은 파일을 `ADDED`로 표시합니다. 이후 안정된 metadata는 `UNCHANGED`, size/mtime/file ID가 바뀌면 `MODIFIED`, 이전 항목이 사라지면 `MISSING`으로 표시합니다. 새로 발견된 파일의 안정 metadata가 missing 이전 항목과 일치하면 `MOVED_CANDIDATE`로 표시하지만 자동 확정하지 않고 이전 record를 보존합니다. 대소문자 충돌과 link/junction은 `REJECTED`입니다. write는 최대 500개 entry batch로 commit합니다. 중단된 scan은 pending directory cursor를 보존해 재개할 수 있으며 source당 동시에 하나의 scan만 허용합니다. Catalog entry ID는 향후 Inspector 입력으로만 쓰고 Evidence나 Web GPT packet에 자동 포함하지 않습니다.

## Targeted Format Probe, Phase 2

Targeted Format Probe Phase 2는 raw user path가 아닌 `catalog_entry_id`만 받습니다. 선택한 각 entry에 대해 등록된 source root를 다시 검증하고 symlink, junction, 기타 reparse point를 따라가지 않고 catalog-relative file을 해석합니다. 읽기 전에 현재 `size`, `mtime_ns`, filesystem ID를 Catalog snapshot과 비교하며 오래된 entry는 `STALE_CATALOG_ENTRY`로 거부해 먼저 rescan하도록 합니다.

Probe는 request당 최대 50개 entry와 파일당 128KB로 제한되며 현재 detector registry도 제한된 prefix window만 sample합니다. 결과에는 Catalog asset kind와 probe가 감지한 asset kind를 별도로 저장하고 detector version, `bytes_read`, sample bytes만 대상으로 한 SHA-256, confidence가 붙은 format 후보, extension match status, 다음 Inspector hint 하나를 저장합니다. hint는 `UNITY_BUNDLE`, `PMX`, `FBX`, `GLTF`, `TEXTURE`, `ARCHIVE`, `AUDIO`, `EXECUTABLE`, `NONE` 중 하나입니다. 이 단계에서는 `full_parse_allowed`가 계속 `false`입니다.

registry는 강한 signature만으로 UnityFS/Raw/Web bundle, PMX/PMD, FBX binary/ASCII, GLB/glTF, PNG/JPEG/DDS/KTX1/KTX2/WEBP/BMP/TIFF, ZIP/7z/RAR/GZIP/XZ, PE/ELF, WAV/OGG/FLAC/MP3를 인식합니다. TGA처럼 약한 extension 형식은 extension만으로 확정하지 않습니다. probe가 충돌하거나 증거가 부족하면 `detected_format`은 `UNKNOWN`으로 남습니다. mismatch가 rename, rewrite, 자동 Evidence attachment를 일으키지 않습니다. Catalog와 마찬가지로 Phase 2는 local-only이며 app-server RPC, `command/exec`, `thread/start`, `turn/start`를 호출하지 않습니다.

Phase 2 cache 재사용은 보수적으로 동작합니다. cache lookup 전에 현재 Catalog metadata를 검증하고 detector 크기의 bounded sample만 읽어 sample만 hash한 뒤 `size`, `mtime_ns`, `file_id`, `sample_sha256`로 cache identity를 만듭니다. 동일 identity의 이전 `COMPLETED` 결과만 재사용합니다. `FAILED`, `REJECTED`, `STALE` 시도는 영구 cache entry가 되지 않으며 같은 파일 상태에 대해 다시 시도할 수 있습니다. 각 probe attempt는 번호와 시각을 가지며 앱 시작 시 orphaned `PENDING`/`PROBING` 행을 원자적으로 `FAILED/probe_interrupted`로 복구합니다.

confidence와 `next_inspector`도 보수적으로 계산합니다. 정확히 하나의 detector가 `HIGH` confidence에 도달할 때만 `next_inspector`를 지정합니다. 구조 검사는 GLB version/declared length, bounded glTF JSON `asset.version`, PMX/PMD header version, BMP size/offset/DIB field, MP3 frame-header field를 검증합니다. bare FBX ASCII banner, fake `BM`, fake `Pmd`, fake `FF E0`, malformed glTF JSON, malformed GLB 같은 약한 증거는 `MEDIUM` 또는 `UNKNOWN`으로 남겨 downstream Inspector와 Codex token을 잘못된 추측에 쓰지 않습니다.

## Token Savings Ledger

## WSL2 재현성 검사

정제된 `SAFE_CANDIDATE` WSL2_BWRAP 결과가 있으면 local-only repeatability check를 고정 workload로 10회 실행할 수 있습니다. 각 시도는 새 capsule과 bwrap process를 받고 `/work`를 read-only working directory로 하는 allowlisted environment를 사용합니다. capsule read, host/outside read, write, temporary-file 처리, loopback network를 확인합니다. 사용자 command, source root, Windows mount, app-server RPC, model turn은 사용하지 않습니다.

저장하는 것은 가려진 count, 최종 상태, canonical result hash, duration, 정제된 error code뿐입니다. raw output, fixture 내용, path, canary는 process 밖으로 나가지 않습니다. mismatch는 `NONDETERMINISTIC`, boundary failure는 `UNSAFE_HOST_FS`, `UNSAFE_WRITE`, `UNSAFE_NETWORK`, timeout/marker/process failure는 `ERROR`입니다. `SAFE_CANDIDATE` 자체는 바뀌지 않으며 모든 상태에서 live 실행은 잠겨 있습니다. 같은 configuration의 동시 request는 single-flight로 처리하고 orphaned `RUNNING` record는 시작 시 `ERROR/probe_interrupted`로 복구합니다.

Child workload는 `os.write`로 정확히 하나의 `CODEXGATE_REPRO_V1:<base64url canonical JSON>` frame을 출력하며 `-I -S -u`로 실행합니다. Host stdout과 stderr는 분리해 capture합니다. 주변 blank line과 CRLF/LF는 normalize하지만 frame 누락, 중복, 추가 non-empty frame line, non-canonical JSON, invalid base64url, 잘못된 iteration, fixture mismatch는 정제된 protocol code로 거부합니다. stderr warning은 진단에 바이트 길이만 기여합니다.

Fixture는 `build_repro_fixture_bytes()`로 attempt당 한 번 만들고 binary `wb`와 flush/fsync로 기록하며 그 immutable bytes에서 직접 hash합니다. child는 공유 고정 상대 fixture path를 `rb`로 열고 iteration은 frame field일 뿐입니다. write-denial 경로는 분리하고 stable result hash에서는 iteration을 제외하되 fixture hash와 여섯 boundary 결과는 유지합니다.

Token Savings Ledger Phase 1은 raw prompt, raw response, full log를 저장하지 않고 observed, imported, estimated usage signal을 기록합니다. Ledger run, usage event, 수동 import baseline을 추적하고 `/api/token-ledger/*` endpoint를 통해 JSON 또는 Markdown summary를 제공합니다.

## Contract preview와 immutable instance

Egress-contract preview는 순수 read 작업입니다. complete runtime identity(identity version, runtime/launch-spec digest, binary digest), 현재 Isolation identity, Repro proof, provider configuration, policy version에서 `current_binding_hash`와 `preview_hash`를 다시 계산합니다. Runtime이나 Harness permission을 부여하지 않으며 DB row를 쓰지 않습니다.

기존 singleton table은 차단 결과의 audit trail로 유지하지만 환경이 바뀐 뒤에는 blocked snapshot을 current preview로 반환하지 않습니다. Immutable instance는 별도 instance table에 있고 생성 당시 identity에 계속 결속됩니다. 생성 request는 현재 `expected_preview_hash`를 제공해야 하며 transaction이 binding을 다시 계산해 stale 값은 `preview_stale`로 거부합니다. 일치하는 identity와 hash request는 idempotent하게 기존 instance를 반환합니다. HTTP API는 `GET /api/isolation/wsl/egress-contract/preview`를 제공하고 POST body에 hash를 요구합니다. Authentication은 미구성 상태로 남고 모든 start는 잠겨 있습니다.

성공한 live run이 기록되지 않았다면 보고서에는 `실제 토큰 절감 미측정`을 표시합니다.

## Phase 4.3 Test I/O Fuse

pytest session은 collection 전에 fail-fast fuse를 설치합니다. 실제 `subprocess.run`, `Popen`, `asyncio.create_subprocess_exec`, `os.system`, application socket connect/bind는 운영체제 resource가 만들어지기 전에 정제된 `unexpected_real_io_in_test` 오류를 발생시킵니다. 따라서 Phase 4.3 테스트는 no-I/O supervisor만 주입합니다. 봉인된 `RUNNING` claim 전에는 production executor를 만들지 않습니다. Windows junction helper 호출은 PowerShell을 시작하지 않고 test temporary directory 안에서 emulation합니다. 사고 감사는 저장소 밖 `TEST_REAL_IO_INCIDENT.json`에 유지하며 raw argument, path, output, process ID, socket ID를 넣지 않습니다.

## Offline Codex supervisor 진단

봉인된 Offline Codex supervisor는 정확히 한 줄의 `CODEXGATE_CODEX_SUPERVISOR_V1:<base64url canonical JSON>`을 출력합니다. payload에는 `status`, `stage`, 네 provenance counter(`supervisor`, `broker_bwrap`, `relay_codex_bwrap`, `codex_cli`), `cleanup_ok`, implementation digest, request count, request/response/output digest, 민감 header 제거 flag만 들어갑니다. prompt, response, token, path, argv, environment, raw process output은 포함하지 않습니다. 유효 stage는 `BOOT`, `CLAIM_VALIDATE`, `SPEC_VALIDATE`, `RUNTIME_VALIDATE`, `BROKER_SPAWN`, `BROKER_READY`, `RELAY_CODEX_SPAWN`, `RESPONSE_VALIDATE`, `CLEANUP`입니다.

Supervisor workload failure는 frame으로 봉인하고 transport exit를 0으로 둡니다. Python 시작 전 실패나 WSL transport 종료만 transport error입니다. frame 누락, 중복, 추가 field, non-canonical frame, hash 불일치는 서로 다른 protocol 진단으로 구분합니다. counter는 해당 spawn이 성공한 뒤에만 증가하며 기존 Codex process를 포함하지 않습니다. `BROKER_SPAWN` 전에는 child process가 모두 0이어야 합니다. legacy `canary_exit_invalid` 값은 기존 행에서 immutable하게 보존하고 조회 시 legacy 진단으로 표시하며, 새 supervisor failure는 stage별 정제 code를 사용합니다. 모든 테스트는 no-I/O fuse 아래에서 실행하고 normal runtime/live execution lock은 닫혀 있습니다.

봉인된 provider authority는 `127.0.0.1:8788` 하나입니다. provider TOML, relay listener, broker Host 검증은 Egress Contract 상수에서 파생됩니다. supervisor는 private CODEX_HOME을 만들고 canonical TOML을 binary mode로 기록해 relay/Codex capsule에 read-only로 bind합니다. 실행별 in-memory token만 capsule에 전달합니다. 고정 prompt는 고정 Codex child stdin으로만 보냅니다. relay는 bounded `POST /v1/responses` 하나를 accept하고 sole AF_UNIX hop 전에 Authorization/Cookie/Proxy-*를 제거하며 broker는 deterministic response 하나를 반환합니다. 두 번째 connection, request, WebSocket, host, path, model은 fail-closed입니다.

`PASSED`는 관측된 supervisor/broker-bwrap/relay-bwrap/Codex count `1/1/1/1`, request 하나, 봉인 기대값과 일치하는 세 proof digest, marker digest, 두 child의 cleanup 성공을 추가로 요구합니다. 고정 `codex-cli 0.145.0` request wire format은 Phase 4.4 proof module로 표현됩니다. tagged source digest가 일치하지 않으면 production supervisor는 child를 spawn하기 전에 `RUNTIME_VALIDATE`에서 차단하며, 추측한 wire format으로는 pass를 만들 수 없습니다.

## Codex 0.145.0 wire-contract proof

`app/codex_wire_contract.py`는 순수 no-I/O contract boundary입니다. 공식 `openai/codex` `rust-v0.145.0` source에 대해 상대 경로, source digest, field 이름, event 이름, hash만 기록합니다. no-tool stream은 엄격하게 `response.output_item.done` 두 개 뒤 `response.completed`가 와야 합니다. 누락, 중복, 추가, failed, error, tool event는 거부합니다. Request model, prompt hash, streaming, no-tools, `parallel_tool_calls=false`를 request 전에 확인합니다.

정확한 tagged source byte를 독립적으로 검증한 SHA-256이 모두 준비되기 전에는 proof를 `UNPROVEN`으로 유지하고 production runner를 `codex_wire_contract_unproven`으로 차단합니다. Contract hash는 runner implementation hash의 일부이므로 wire proof가 바뀌면 기존 PASSED 결과, Permit, Window를 재사용할 수 없습니다. 외부 proof snapshot에는 source body, prompt, response, path, credential, raw output을 저장하지 않습니다.
