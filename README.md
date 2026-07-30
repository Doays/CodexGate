# Codex Gate

Codex Gate는 ChatGPT식 계획과 Codex 실행을 분리하는 로컬 전용 제어면입니다. 프로젝트 범위, 권한, 모델 선택, 실행 상태를 한 곳에서 검증하며 기본 실행 권한은 잠겨 있습니다.

## 빠른 시작

PowerShell에서 실행합니다.

```powershell
cd C:\Users\82109\Documents\Codex\2026-07-26\dl\outputs\CodexGate
python -m pip install -r requirements.txt
.\run.ps1
```

브라우저에서 `http://127.0.0.1:8787`을 엽니다. 공식 시작 스크립트는 127.0.0.1에만 바인딩합니다. 개발 중 자동 reload가 필요하면 `.\run_dev.ps1`을 사용합니다.

## 핵심 원칙

- 기본 권한은 Read Only입니다. Workspace Write, Runtime start, 일반 live 실행, Ultra는 잠겨 있습니다.
- Runtime identity, Isolation Canary, Repro, immutable Contract를 현재 결속으로 검증합니다.
- 외부 네트워크·DNS·실제 모델 요청·app-server RPC는 봉인된 검증 경로에서 사용하지 않습니다.
- Offline Codex Canary는 고정 wire contract와 로컬 fake Responses API만 대상으로 합니다.
- Permit·Window·execution claim은 1회용이며 nonce 원문은 DB·로그·DOM·URL·스토리지에 저장하지 않습니다.
- 실제 provider token이 없으면 절감 판정은 항상 `NOT_COMPARABLE`입니다.
- 경로, credential, prompt, response, argv 원문은 API와 로그에 노출하지 않습니다.

## 증명 체인

1. WSL/bwrap Isolation Canary로 읽기·쓰기·임시 파일·네트워크 경계를 확인합니다.
2. 같은 config와 tool 결속의 Repro 결과가 `SAFE_REPRODUCIBLE 10/10/10`인지 확인합니다.
3. Runtime identity와 Repro에 결속된 immutable Egress Contract preview를 계산합니다.
4. 현재 Contract와 runner 구현에 결속된 Actual Harness 증명이 있어야 다음 단계가 준비됩니다.
5. Offline Canary는 명시적인 로컬 UI 클릭 한 번으로 Permit → Window → one-shot 순서로 소비됩니다.

각 단계는 실패 시 즉시 중단하며 retry, fallback, reroute, 자동 backfill을 사용하지 않습니다. 과거 차단 snapshot과 immutable instance는 수정하거나 덮어쓰지 않습니다.

## 오프라인 Canary 정책

- 실행 endpoint는 동일 Origin의 127.0.0.1 요청만 허용합니다.
- 통합 실행 요청 body에는 nonce, model, prompt, argv, 경로를 받지 않습니다.
- 서버가 내부에서 capability를 발급하고 한 transaction에서 claim하며, 실행 전 두 capability를 소비합니다.
- Codex 요청은 `/v1/responses` 한 건만 허용하고 tools, WebSocket, 재시도, 명령 실행, 파일 변경을 차단합니다.
- `CODEX_HOME`과 임시 상태는 실행별 격리 공간을 사용하며 호스트의 인증 파일을 bind하지 않습니다.
- 성공은 supervisor·broker·relay/Codex·Codex 프로세스와 request/response/output 증명이 모두 확인될 때만 인정합니다.

## 저장 데이터와 안전성

앱 상태는 `CODEX_GATE_HOME` 아래 SQLite에 저장됩니다. Ledger에는 계획값을 `ESTIMATED`, 실제 로컬 관측값을 `OBSERVED`로 분리해 기록합니다. provider token은 저장하지 않으며 fake usage는 실제 사용량으로 계산하지 않습니다.

테스트 기본 경로에는 Test I/O Fuse가 적용되어 subprocess, WSL, bwrap, socket, 외부 네트워크 생성이 차단됩니다. 운영 경로도 기본적으로 잠겨 있고 명시적인 봉인 조건을 모두 만족해야만 선택됩니다.

## 검증 명령

```powershell
python -m pytest -q
python -m pip check
git diff --check
```

실제 WSL·Codex·외부 모델 실행이 필요한 작업은 별도 승인된 운영 절차에서만 수행합니다. 이 저장소의 기본 테스트와 UI는 외부 모델 토큰 0을 유지합니다.

## 관련 파일

- `run.ps1`: 로컬 API 시작
- `app/main.py`: HTTP API와 UI 상태 연결
- `app/codex_process_canary.py`: Offline Canary 상태·Permit·one-shot 흐름
- `app/codex_process_executor_wsl.py`: 봉인된 WSL supervisor 명세와 frame 검증
- `app/codex_wire_contract.py`: Codex Responses wire contract 검증
- `tests/`: Test I/O Fuse 아래의 순수·가짜 실행 검증
