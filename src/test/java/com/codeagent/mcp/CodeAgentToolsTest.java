package com.codeagent.mcp;

import com.codeagent.mcp.findings.FindingStore;
import com.codeagent.mcp.tools.Args;
import com.codeagent.mcp.tools.CodeAgentTools;
import com.codeagent.mcp.tools.ToolDef;
import com.codeagent.mcp.tools.ToolException;
import com.codeagent.mcp.workspace.RepositoryRegistry;
import com.codeagent.mcp.workspace.Workspace;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CodeAgentToolsTest {

    static final Path FIXTURE = Path.of("src/test/resources/fixtures/vulnerable-app").toAbsolutePath();

    @TempDir
    Path home;

    private Workspace workspace;
    private CodeAgentTools tools;

    @BeforeEach
    void setUp() {
        workspace = new Workspace(home, List.of("github.com"), 50L * 1024 * 1024, 30);
        tools = new CodeAgentTools(workspace, new RepositoryRegistry(workspace), new FindingStore(workspace.findings()));
        call("load_repository", Map.of("path", FIXTURE.toString()));
    }

    @Test
    void 저장소를_불러오면_코드_그래프_통계를_돌려준다() {
        String result = call("load_repository", Map.of("path", FIXTURE.toString(), "name", "Vuln App"));

        assertThat(result).contains("저장소 id: vuln-app", "진입점 5", "위험 지점 7", "경로(쌍) 6개");
    }

    @Test
    void 인터페이스를_거쳐_SQL_위험_지점까지_가는_경로를_찾는다() {
        String result = call("list_sink_paths", Map.of("repo", "vulnerable-app"));

        assertThat(result).contains("GET /api/users/search  →  [SQL CWE-89] org.springframework.jdbc.core.JdbcTemplate.queryForList");
        assertThat(result).containsPattern("UserService#search\\(String\\)\\(#\\d+\\) › UserServiceImpl#search\\(String\\)");
        assertThat(result).contains("POST /api/users/ping  →  [COMMAND CWE-78]");
        assertThat(result).doesNotContain("/api/users/health");
    }

    @Test
    void 호출하는_쪽을_이름이나_번호로_찾는다() {
        String callers = call("get_callers", Map.of("repo", "vulnerable-app", "node", "UserServiceImpl#findByName"));
        assertThat(callers).contains("UserServiceImpl#search(String)");

        String found = call("find_code_nodes", Map.of("repo", "vulnerable-app", "query", "CommandService#ping", "kind", "METHOD"));
        String id = found.substring(1, found.indexOf(' '));
        String callees = call("get_callees", Map.of("repo", "vulnerable-app", "node", id));
        assertThat(callees).contains("[COMMAND CWE-78] java.lang.Runtime.exec");
    }

    @Test
    void 파일을_줄_번호와_함께_읽고_저장소_밖은_막는다() {
        String file = call("read_file", Map.of("repo", "vulnerable-app",
                "path", "src/main/java/com/example/vuln/service/UserServiceImpl.java", "start_line", 24, "end_line", 25));
        assertThat(file).contains("(24-25 / 전체 27줄)", "24 |         String sql = \"select * from users where name = '\" + name + \"'\";");

        assertThatThrownBy(() -> call("read_file", Map.of("repo", "vulnerable-app", "path", "../../../build.gradle")))
                .isInstanceOf(ToolException.class).hasMessageContaining("저장소 밖");
    }

    @Test
    void 코드를_정규식으로_검색한다() {
        assertThat(call("grep_code", Map.of("repo", "vulnerable-app", "pattern", "queryForList")))
                .contains("src/main/java/com/example/vuln/service/UserServiceImpl.java:25:");
        assertThat(call("grep_code", Map.of("repo", "vulnerable-app", "pattern", "@Valid"))).isEqualTo("일치하는 줄 없음");
    }

    @Test
    void 발견을_기록하고_판정하고_보고서로_내보낸다() throws Exception {
        String recorded = call("record_finding", Map.of(
                "repo", "vulnerable-app",
                "title", "사용자 검색 API의 SQL 인젝션",
                "cwe", "cwe-89",
                "severity", "high",
                "confidence", "high",
                "description", "name 이 SQL 문자열에 이어 붙여진다",
                "exploit_scenario", "GET /api/users/search?name=' OR '1'='1",
                "evidence", List.of(Map.of("file", "src/main/java/com/example/vuln/service/UserServiceImpl.java", "line", 24, "note", "문자열 결합")),
                "entry_point", "GET /api/users/search"));
        assertThat(recorded).startsWith("발견 F1 기록함");
        call("record_finding", Map.of("repo", "vulnerable-app", "title", "헬스 체크 정보 노출", "cwe", "CWE-200",
                "severity", "low", "confidence", "low", "description", "상수만 반환",
                "evidence", List.of(Map.of("file", "src/main/java/com/example/vuln/web/UserController.java", "line", 46, "note", "ok"))));

        assertThat(call("submit_verdict", Map.of("repo", "vulnerable-app", "finding_id", "F1", "verdict", "confirmed",
                "reasoning", "검증 없음", "severity", "critical"))).contains("확정", "심각도 critical");
        call("submit_verdict", Map.of("repo", "vulnerable-app", "finding_id", "f2", "verdict", "rejected", "reasoning", "상수"));

        assertThat(call("list_findings", Map.of("repo", "vulnerable-app")))
                .isEqualTo("F1 [확정] critical CWE-89 사용자 검색 API의 SQL 인젝션 · GET /api/users/search\n"
                        + "F2 [기각(오탐)] low CWE-200 헬스 체크 정보 노출");

        String markdown = call("export_report", Map.of("repo", "vulnerable-app"));
        assertThat(markdown).contains("확정 1 · 검증 대기 0 · 판단 불가 0 · 기각(오탐) 1", "## F1. 사용자 검색 API의 SQL 인젝션")
                .doesNotContain("## F2.");
        Path saved = Path.of(markdown.substring("저장함: ".length(), markdown.indexOf('\n')));
        assertThat(saved).startsWith(workspace.reports()).exists();

        String sarif = call("export_report", Map.of("repo", "vulnerable-app", "format", "sarif"));
        String sarifJson = Files.readString(Path.of(sarif.substring("저장함: ".length()).strip()));
        assertThat(sarifJson).contains("\"version\" : \"2.1.0\"", "\"ruleId\" : \"CWE-89\"", "\"level\" : \"error\"")
                .doesNotContain("CWE-200");
    }

    @Test
    void 발견은_서버를_다시_켜도_남는다() {
        call("record_finding", Map.of("repo", "vulnerable-app", "title", "명령 인자 주입", "cwe", "CWE-78",
                "severity", "medium", "confidence", "medium", "description", "host 를 이어 붙임",
                "evidence", List.of(Map.of("file", "src/main/java/com/example/vuln/service/CommandService.java", "line", 11, "note", "exec"))));

        CodeAgentTools restarted = new CodeAgentTools(workspace, new RepositoryRegistry(workspace), new FindingStore(workspace.findings()));
        String loaded = run(restarted, "load_repository", Map.of("path", FIXTURE.toString()));

        assertThat(loaded).contains("이전에 기록한 발견 1개");
        assertThat(run(restarted, "list_findings", Map.of("repo", "vulnerable-app"))).contains("F1 [검증 대기] medium CWE-78 명령 인자 주입");
    }

    @Test
    void 잘못된_입력은_고칠_수_있게_알려준다() {
        assertThatThrownBy(() -> call("list_sink_paths", Map.of("repo", "없는-저장소")))
                .hasMessageContaining("load_repository 를 먼저 호출할 것");
        assertThatThrownBy(() -> call("record_finding", Map.of("repo", "vulnerable-app", "title", "t", "cwe", "CWE-1",
                "severity", "urgent", "confidence", "high", "description", "d",
                "evidence", List.of(Map.of("file", "a.java", "line", 1, "note", "n")))))
                .hasMessageContaining("severity");
        assertThatThrownBy(() -> call("record_finding", Map.of("repo", "vulnerable-app", "title", "t", "cwe", "CWE-1",
                "severity", "low", "confidence", "high", "description", "d", "evidence", List.of())))
                .hasMessageContaining("evidence");
        assertThatThrownBy(() -> call("submit_verdict", Map.of("repo", "vulnerable-app", "finding_id", "F9",
                "verdict", "confirmed", "reasoning", "r")))
                .hasMessageContaining("발견 없음: F9");
        assertThatThrownBy(() -> call("load_repository", Map.of()))
                .hasMessageContaining("path 와 git_url 중 하나만");
    }

    @Test
    void 허용하지_않는_Git_주소는_클론하지_않는다() {
        assertThatThrownBy(() -> call("load_repository", Map.of("git_url", "http://github.com/owner/repo.git")))
                .hasMessageContaining("https 주소만");
        assertThatThrownBy(() -> call("load_repository", Map.of("git_url", "https://internal.example.com/owner/repo.git")))
                .hasMessageContaining("허용하지 않는 호스트");
    }

    private String call(String tool, Map<String, Object> args) {
        return run(tools, tool, args);
    }

    private static String run(CodeAgentTools tools, String tool, Map<String, Object> args) {
        ToolDef def = tools.all().stream().filter(t -> t.name().equals(tool)).findFirst().orElseThrow();
        return def.handler().apply(new Args(args));
    }
}
