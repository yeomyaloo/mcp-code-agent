package com.codeagent.mcp;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.ServerParameters;
import io.modelcontextprotocol.client.transport.StdioClientTransport;
import io.modelcontextprotocol.json.McpJsonDefaults;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.GetPromptRequest;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import io.modelcontextprotocol.spec.McpSchema.Tool;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 채팅 클라이언트처럼 서버를 별도 프로세스로 띄우고 stdio MCP 로 대화한다.
 */
class McpProtocolTest {

    @TempDir
    Path home;

    @Test
    void 클라이언트가_서버를_띄워_도구와_프롬프트를_쓴다() {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        ServerParameters params = ServerParameters.builder(java)
                .args("-Dfile.encoding=UTF-8", "-Dstdout.encoding=UTF-8", "-cp", System.getProperty("java.class.path"),
                        McpCodeAgent.class.getName())
                .env(Map.of("MCP_CODE_AGENT_HOME", home.toString()))
                .build();

        try (McpSyncClient client = McpClient.sync(new StdioClientTransport(params, McpJsonDefaults.getMapper()))
                .requestTimeout(Duration.ofSeconds(60))
                .initializationTimeout(Duration.ofSeconds(60))
                .build()) {
            var init = client.initialize();
            assertThat(init.serverInfo().name()).isEqualTo("mcp-code-agent");
            assertThat(init.instructions()).contains("load_repository");

            assertThat(client.listTools().tools()).extracting(Tool::name)
                    .contains("load_repository", "list_sink_paths", "read_file", "record_finding", "submit_verdict", "export_report");
            Tool readFile = client.listTools().tools().stream().filter(t -> t.name().equals("read_file")).findFirst().orElseThrow();
            assertThat(readFile.annotations().readOnlyHint()).isTrue();

            CallToolResult loaded = client.callTool(new CallToolRequest("load_repository",
                    Map.of("path", CodeAgentToolsTest.FIXTURE.toString())));
            assertThat(loaded.isError()).isFalse();
            assertThat(text(loaded)).contains("저장소 id: vulnerable-app", "위험 지점 7");

            CallToolResult paths = client.callTool(new CallToolRequest("list_sink_paths", Map.of("repo", "vulnerable-app")));
            assertThat(text(paths)).contains("GET /api/users/search  →  [SQL CWE-89]");

            // 입력 오류는 예외가 아니라 isError 결과로 돌아와서 Claude 가 고쳐 부를 수 있다
            CallToolResult error = client.callTool(new CallToolRequest("read_file", Map.of("repo", "vulnerable-app", "path", "../../x")));
            assertThat(error.isError()).isTrue();
            assertThat(text(error)).contains("저장소 밖");

            var prompt = client.getPrompt(new GetPromptRequest("security_audit", Map.of("target", "https://github.com/o/r.git")));
            assertThat(((TextContent) prompt.messages().get(0).content()).text())
                    .contains("load_repository 를 git_url=\"https://github.com/o/r.git\"", "submit_verdict");
        }
    }

    private static String text(CallToolResult result) {
        return ((TextContent) result.content().get(0)).text();
    }
}
