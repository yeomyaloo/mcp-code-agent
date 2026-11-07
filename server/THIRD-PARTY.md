# Third-party libraries / 함께 배포하는 라이브러리

`server/lib/` contains the prebuilt MCP server (`mcp-code-agent-*.jar`, Apache-2.0) and its unmodified runtime dependencies, so the Claude Code plugin works without a build step. Each jar keeps its own license and notice files under `META-INF/`. Regenerate with `./gradlew pluginServer`.

`server/lib/`에는 미리 빌드한 MCP 서버와, 고치지 않은 런타임 의존 라이브러리가 들어 있다. 각 jar의 `META-INF/`에 원래 라이선스·고지 파일이 그대로 있다.

| Library | License |
|---|---|
| MCP Java SDK (`mcp`, `mcp-core`, `mcp-json-jackson3`) | MIT |
| JavaParser (`javaparser-core`, `javaparser-symbol-solver-core`) | Apache-2.0 / LGPL-3.0 (dual) |
| Javassist | Apache-2.0 / MPL-1.1 / LGPL-2.1 (tri) |
| Eclipse JGit | EDL-1.0 (BSD-3-Clause) |
| JavaEWAH | Apache-2.0 |
| Jackson 3 (`jackson-core`, `jackson-databind`, `jackson-dataformat-yaml`), `jackson-annotations` | Apache-2.0 |
| SnakeYAML Engine | Apache-2.0 |
| networknt json-schema-validator | Apache-2.0 |
| ethlo ITU | Apache-2.0 |
| Reactor Core, Reactive Streams | Apache-2.0, MIT-0 |
| Guava, failureaccess, listenablefuture, j2objc-annotations, error_prone_annotations | Apache-2.0 |
| Apache Commons Codec | Apache-2.0 |
| Checker Framework qual | MIT |
| JSR-305 annotations | BSD-3-Clause |
| SLF4J API, SLF4J Simple | MIT |
