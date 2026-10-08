package com.codeagent.mcp.workspace;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * 서버가 쓰는 폴더와 설정. 환경 변수로 바꿀 수 있다.
 *
 * @param home         클론, 발견, 보고서를 두는 폴더 (MCP_CODE_AGENT_HOME, 기본 ~/.mcp-code-agent)
 * @param gitHosts     클론을 허용하는 호스트 (MCP_CODE_AGENT_GIT_HOSTS, 쉼표로 구분)
 * @param maxRepoBytes 클론한 저장소 크기 상한
 */
public record Workspace(Path home, List<String> gitHosts, long maxRepoBytes, int cloneTimeoutSeconds) {

    public static Workspace fromEnvironment() {
        String home = System.getenv("MCP_CODE_AGENT_HOME");
        String hosts = System.getenv("MCP_CODE_AGENT_GIT_HOSTS");
        return new Workspace(
                home == null || home.isBlank() ? Path.of(System.getProperty("user.home"), ".mcp-code-agent") : Path.of(home),
                hosts == null || hosts.isBlank()
                        ? List.of("github.com", "gitlab.com", "bitbucket.org")
                        : Arrays.stream(hosts.split(",")).map(String::strip).filter(h -> !h.isEmpty()).toList(),
                500L * 1024 * 1024,
                120);
    }

    public Path repos() {
        return home.resolve("repos");
    }

    public Path findings() {
        return home.resolve("findings");
    }

    public Path reports() {
        return home.resolve("reports");
    }
}
