# mcp-code-agent

채팅 앱(Claude Code, Claude Desktop)에 연결하는 stdio MCP 서버. Claude가 판단하고, 이 서버는 Java/Spring 코드 그래프·파일 읽기·발견 기록·보고서를 맡는다. be-code-agent(`../code-agent`)의 코드 그래프 엔진을 가져와 DB 없이 돌게 만든 독립 버전.

## 명령

```bash
./gradlew test          # 테스트 (DB·네트워크·API 키 불필요)
./gradlew installDist   # build/install/mcp-code-agent/bin/mcp-code-agent(.bat)
```

- 빌드는 JDK 21 toolchain, 바이트코드는 `release 17`. 채팅 앱이 PATH의 java(17일 수 있음)로 띄우므로 Java 21 전용 API(`getFirst`, `addFirst` 등)를 쓰지 않는다.
- Windows PowerShell에서는 `.\gradlew.bat`.

## 구조

- `McpCodeAgent`: 서버 진입점. 도구는 `tools/CodeAgentTools.all()`, 프롬프트는 `Prompts`.
- 새 도구는 `CodeAgentTools`에 `ToolDef`를 추가하고 `all()`에 넣는다. 입력 오류는 `ToolException`으로 던진다(isError 결과로 Claude에게 전달됨).
- 파일 접근은 반드시 `RepoFiles.resolve()`로 경로를 검사한다(저장소 밖 차단).
- `codegraph/`의 `JavaProject`, `TypeResolver`, `EntryPointDetector`, `SinkRules`, `CodeGraphBuilder`, `CodeGraphDraft`와 `source/`는 be-code-agent에서 복사했다. 위험 지점 규칙이나 진입점 탐지를 고치면 두 저장소를 같이 맞춘다.

## 규칙

- **표준 출력은 MCP 메시지 전용이다.** `System.out`에 쓰지 않는다. 로그는 SLF4J(slf4j-simple, 표준 오류)로만.
- 도구 설명, 결과 문구, 주석, 테스트 메서드 이름은 한국어.
- 분석 대상 코드는 읽기만 한다. 빌드하거나 실행하지 않는다.
- 도구나 프롬프트를 바꾸면 README의 도구 표, 프롬프트 표도 갱신한다.
- 작업이 끝나고 `./gradlew test`가 통과하면 커밋하고 푸시해도 된다.
- 사용자에게 설명과 요약은 한국어로 한다.
