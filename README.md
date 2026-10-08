# mcp-code-agent

**채팅에서 쓰는 AI 코드 보안 분석 에이전트 (MCP 서버)**

Claude Code, Claude Desktop 같은 채팅 앱에 연결하는 [MCP](https://modelcontextprotocol.io) 서버다. 채팅창에 "이 저장소 보안 분석해줘"라고 하면, Claude가 이 서버의 도구로 Java/Spring 코드의 **진입점 → 위험 지점** 경로를 따라가며 취약점을 찾고, 입장을 바꿔 다시 검증하고, 보고서를 만든다.

- **API 키가 필요 없다.** 채팅 앱에 로그인한 구독(Pro, Max, Team 등)으로 돈다.
- **DB도 서버도 필요 없다.** Java만 있으면 된다. 코드 그래프는 메모리에, 발견은 JSON 파일에 둔다.
- [be-code-agent](https://github.com/yeomyaloo/be-code-agent)(Spring Boot 백엔드 + PostgreSQL + Anthropic API)와 같은 코드 그래프 엔진을 쓰는 **독립 버전**이다.

## 구조: Claude는 두뇌, MCP 서버는 손발

```
 ┌─────────── 채팅 앱 (Claude Code / Claude Desktop) ───────────┐
 │  Claude = 두뇌                                                │
 │  · 어떤 경로를 조사할지, 어떤 파일을 읽을지 정한다              │
 │  · 취약한지 판단한다 (Worker 역할)                             │
 │  · 입장을 바꿔 다시 검증한다 (Verifier 역할)                   │
 └───────────────┬───────────────────────────────▲──────────────┘
                 │ 도구 호출 (MCP, 표준 입출력)    │ 결과 텍스트
 ┌───────────────▼───────────────────────────────┴──────────────┐
 │  mcp-code-agent = 손발                                       │
 │  · 코드 그래프: JavaParser 로 진입점·위험 지점·호출 관계 추출   │
 │  · 파일 읽기·검색 (저장소 밖 접근 차단)                        │
 │  · 발견 기록·판정 저장 (~/.mcp-code-agent/findings/*.json)     │
 │  · 보고서 (Markdown, SARIF 2.1.0)                            │
 └──────────────────────────────────────────────────────────────┘
```

be-code-agent와 비교하면 다음과 같다.

| | be-code-agent | mcp-code-agent |
|---|---|---|
| 두뇌(LLM) | 백엔드가 Anthropic API 호출 (API 키 필요) | 채팅 앱의 Claude (구독 로그인) |
| 반복 실행 | 백엔드 `AgentLoop` | 채팅 앱이 알아서 반복 |
| Worker / Verifier | 백엔드가 별도 에이전트로 실행 | 채팅의 Claude가 차례로 맡음 (Claude Code는 서브에이전트로 나눌 수 있음) |
| 저장 | PostgreSQL | 메모리 + JSON 파일 |
| 화면 | [fe-code-agent](https://github.com/yeomyaloo/fe-code-agent) | 채팅창 |

## 설치

### 요구 사항

- **Java 17 이상** (`java -version` 으로 확인. 빌드할 때 쓰는 JDK 21은 Gradle이 자동으로 받는다)

### 빌드

```bash
./gradlew installDist
```

`build/install/mcp-code-agent/bin/` 에 실행 스크립트가 생긴다. Windows는 `mcp-code-agent.bat`, macOS·Linux는 `mcp-code-agent`.

### Claude Code에 연결

```bash
claude mcp add code-agent --scope user -- C:/path/to/mcp-code-agent/build/install/mcp-code-agent/bin/mcp-code-agent.bat
```

`--scope user`면 모든 폴더에서 쓸 수 있다. `claude mcp list`로 연결됐는지 확인한다.

### Claude Desktop에 연결

설정 → 개발자 → 설정 편집에서 `claude_desktop_config.json`을 열고 추가한 뒤 앱을 다시 켠다.

```json
{
  "mcpServers": {
    "code-agent": {
      "command": "C:\\path\\to\\mcp-code-agent\\build\\install\\mcp-code-agent\\bin\\mcp-code-agent.bat"
    }
  }
}
```

## 사용법

### 채팅으로

```
https://github.com/spring-projects/spring-petclinic 저장소 보안 분석해줘
```

```
C:/work/my-api 폴더에서 SQL 인젝션만 찾아줘
```

### 준비된 프롬프트로

분석 순서(조사 → 검증 → 보고)를 담은 프롬프트가 들어 있다. Claude Code에서는 `/` 를 누르면 나온다.

| 프롬프트 | 하는 일 |
|---|---|
| `security_audit` (target, max_paths) | 저장소를 불러와 위험한 경로부터 조사하고, 발견을 다시 검증하고, 보고서를 만든다 |
| `verify_findings` (repo) | 검증 대기 중인 발견만 다시 검증한다 |

### 결과 예시

테스트용 취약 앱(`src/test/resources/fixtures/vulnerable-app`)을 Claude Code(`claude -p`)로 실제 분석한 결과다. Claude가 14턴 동안 도구로 코드를 읽고, SQL 인젝션을 기록하고, 다시 검증해 확정했다.

→ [docs/examples/vulnerable-app-report.md](docs/examples/vulnerable-app-report.md)

## 도구

| 도구 | 하는 일 | 읽기 전용 |
|---|---|---|
| `load_repository` | 폴더 경로 또는 공개 Git https 주소(얕은 클론)로 저장소를 불러와 코드 그래프를 만든다 | |
| `list_repositories` | 불러온 저장소 목록 | ✅ |
| `list_sink_paths` | 진입점 → 위험 지점 호출 경로 (쌍마다 가장 짧은 경로, 짧은 순) | ✅ |
| `list_entry_points` | Spring MVC HTTP 진입점 | ✅ |
| `list_sinks` | 위험 지점 (SQL, COMMAND, PATH, DESERIALIZATION, SSRF, CODE_INJECTION, EXPRESSION_INJECTION, JNDI, OPEN_REDIRECT) | ✅ |
| `find_code_nodes` | 이름으로 클래스·메서드·진입점·위험 지점 찾기 | ✅ |
| `get_callers` / `get_callees` | 호출하는 쪽 / 호출되는 쪽 (인터페이스 → 구현 포함) | ✅ |
| `read_file` | 줄 번호를 붙여 파일 읽기 (한 번에 400줄) | ✅ |
| `grep_code` | 정규식으로 코드 검색 (방어 장치 찾기) | ✅ |
| `record_finding` | 취약점 기록 (근거 코드 위치 필수, 검증 대기 상태) | |
| `submit_verdict` | 발견 판정: confirmed / rejected / uncertain | |
| `list_findings` | 발견 목록 (판정·심각도 순) | ✅ |
| `export_report` | Markdown 또는 SARIF 2.1.0 보고서 저장 | |
| `clear_findings` | 저장소의 발견 모두 지우기 | |

## 설정

| 환경 변수 | 기본값 | 설명 |
|---|---|---|
| `MCP_CODE_AGENT_HOME` | `~/.mcp-code-agent` | 클론(`repos/`), 발견(`findings/`), 보고서(`reports/`)를 두는 폴더 |
| `MCP_CODE_AGENT_GIT_HOSTS` | `github.com,gitlab.com,bitbucket.org` | 클론을 허용하는 호스트 |

## 보안

- **Git 클론**: https와 허용 호스트만 받고, 내부망 주소로 연결되는 호스트는 막는다(SSRF 방지). 최신 커밋 하나만 받고, 서브모듈은 받지 않으며, 저장소 밖을 가리키는 심볼릭 링크는 지운다. 크기 상한은 500MB다.
- **파일 접근**: `read_file`, `grep_code`, `record_finding`은 불러온 저장소 안의 파일만 다룬다(`../`, 심볼릭 링크 차단).
- **코드 실행 없음**: 분석 대상 코드는 읽기만 하고, 빌드하거나 실행하지 않는다.

## 개발

```bash
./gradlew test          # 테스트 (DB·네트워크·API 키 불필요)
./gradlew installDist   # 실행 스크립트 만들기
```

- `CodeAgentToolsTest`: 도구마다 결과와 입력 오류 처리, 발견 저장과 보고서
- `McpProtocolTest`: SDK의 MCP 클라이언트로 서버를 별도 프로세스로 띄워, 실제 stdio 프로토콜로 도구와 프롬프트를 호출한다

### 디렉터리 구조

```
src/main/java/com/codeagent/mcp/
├── McpCodeAgent.java         진입점. stdio MCP 서버, 도구·프롬프트 등록
├── Prompts.java              security_audit, verify_findings 프롬프트와 서버 안내문
├── codegraph/                코드 그래프 (be-code-agent 의 codegraph/ingest 와 같은 엔진)
│   ├── JavaProject, TypeResolver, EntryPointDetector, SinkRules, CodeGraphBuilder
│   └── CodeGraph.java        메모리 그래프, 경로 탐색(BFS), 호출 관계 조회
├── source/                   Git 주소 검사(GitUrlPolicy), 얕은 클론(GitCloner)
├── workspace/                설정(Workspace), 불러온 저장소(RepositoryRegistry)
├── findings/                 발견(Finding), JSON 저장(FindingStore), 보고서(Reports)
└── tools/                    MCP 도구 정의(CodeAgentTools), 인자 검사(Args), 파일 접근(RepoFiles)
```

## 한계

- Java/Spring MVC 코드만 분석한다.
- 코드 그래프는 정적 분석이라 틀릴 수 있다. 그래서 판단은 반드시 Claude가 실제 코드를 읽고 내리게 되어 있다.
- 분석하는 코드는 채팅 앱을 통해 Anthropic으로 전송된다. 외부로 보내면 안 되는 코드는 분석하지 말 것.
- 이 서버를 다른 사람에게 서비스로 제공하는 용도가 아니다. 각자 자기 채팅 앱에 연결해 쓴다.

## 라이선스

[Apache License 2.0](LICENSE)
