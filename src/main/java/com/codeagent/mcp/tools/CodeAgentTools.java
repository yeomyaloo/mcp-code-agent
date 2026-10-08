package com.codeagent.mcp.tools;

import com.codeagent.mcp.codegraph.CodeGraph;
import com.codeagent.mcp.codegraph.CodeGraph.Node;
import com.codeagent.mcp.codegraph.CodeGraph.SinkPath;
import com.codeagent.mcp.codegraph.CodeNodeKind;
import com.codeagent.mcp.findings.Finding;
import com.codeagent.mcp.findings.Finding.Evidence;
import com.codeagent.mcp.findings.Finding.Status;
import com.codeagent.mcp.findings.FindingStore;
import com.codeagent.mcp.findings.Reports;
import com.codeagent.mcp.workspace.LoadedRepository;
import com.codeagent.mcp.workspace.RepositoryRegistry;
import com.codeagent.mcp.workspace.Workspace;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.codeagent.mcp.tools.ToolDef.enumOf;
import static com.codeagent.mcp.tools.ToolDef.integer;
import static com.codeagent.mcp.tools.ToolDef.schema;
import static com.codeagent.mcp.tools.ToolDef.string;

/**
 * 채팅의 Claude 가 쓰는 도구 모음. Claude 가 판단(두뇌)을 맡고, 이 서버는 코드 그래프·파일 접근·기록(손발)을 맡는다.
 */
public class CodeAgentTools {

    private static final List<String> SEVERITIES = List.of("critical", "high", "medium", "low", "info");
    private static final List<String> CONFIDENCES = List.of("high", "medium", "low");
    private static final Map<String, Status> VERDICTS = Map.of(
            "confirmed", Status.CONFIRMED, "rejected", Status.REJECTED, "uncertain", Status.UNCERTAIN);
    private static final Map<String, Object> REPO = string("load_repository 가 돌려준 저장소 id (예: vulnerable-app)");

    private final Workspace workspace;
    private final RepositoryRegistry registry;
    private final FindingStore findings;

    public CodeAgentTools(Workspace workspace, RepositoryRegistry registry, FindingStore findings) {
        this.workspace = workspace;
        this.registry = registry;
        this.findings = findings;
    }

    public List<ToolDef> all() {
        return List.of(loadRepository(), listRepositories(), listSinkPaths(), listEntryPoints(), listSinks(),
                findCodeNodes(), getCallers(), getCallees(), readFile(), grepCode(), recordFinding(), submitVerdict(),
                listFindings(), exportReport(), clearFindings());
    }

    // ---- 저장소 ----

    ToolDef loadRepository() {
        return new ToolDef("load_repository", "저장소 불러오기",
                "분석할 Java/Spring 저장소를 불러와 코드 그래프(진입점, 위험 지점, 호출 관계)를 만든다. "
                        + "path(이 컴퓨터의 폴더) 또는 git_url(공개 https 저장소, 얕은 클론) 중 하나를 준다. "
                        + "같은 저장소를 다시 부르면 다시 파싱(Git 이면 최신 커밋으로 다시 클론)한다. 분석의 첫 단계.",
                schema(props(
                        "path", string("분석할 폴더의 절대 경로"),
                        "git_url", string("공개 Git 저장소 https 주소 (github.com, gitlab.com, bitbucket.org)"),
                        "branch", string("git_url 의 브랜치. 생략하면 기본 브랜치"),
                        "name", string("저장소 id 로 쓸 이름. 생략하면 폴더·저장소 이름")), List.of()),
                false, true, args -> {
            String path = args.optionalString("path").orElse(null);
            String gitUrl = args.optionalString("git_url").orElse(null);
            if ((path == null) == (gitUrl == null)) {
                throw new ToolException("path 와 git_url 중 하나만 줄 것");
            }
            String name = args.optionalString("name").orElse(null);
            LoadedRepository repo = gitUrl != null
                    ? registry.loadGit(gitUrl, args.optionalString("branch").orElse(null), name)
                    : registry.loadLocal(path, name);
            CodeGraph.Stats s = repo.graph().stats();
            int pairs = repo.graph().sinkPaths(12, 1000).size();
            int existing = findings.list(repo.id()).size();
            StringBuilder sb = new StringBuilder();
            sb.append("저장소 id: ").append(repo.id()).append('\n')
                    .append("대상: ").append(repo.origin()).append('\n')
                    .append("파일 ").append(s.files()).append(" · 클래스 ").append(s.classes())
                    .append(" · 메서드 ").append(s.methods()).append(" · 진입점 ").append(s.entryPoints())
                    .append(" · 위험 지점 ").append(s.sinks()).append('\n')
                    .append("호출 ").append(s.callEdges()).append(" · 상속 연결 ").append(s.overrideEdges())
                    .append(" · 타입을 알 수 없는 호출 ").append(s.unresolvedCalls()).append('\n')
                    .append("진입점 → 위험 지점 경로(쌍) ").append(pairs).append("개. list_sink_paths 로 볼 수 있음\n");
            if (!s.parseErrors().isEmpty()) {
                sb.append("파싱 오류 ").append(s.parseErrors().size()).append("개: ")
                        .append(String.join("; ", s.parseErrors().subList(0, Math.min(5, s.parseErrors().size())))).append('\n');
            }
            if (existing > 0) {
                sb.append("이전에 기록한 발견 ").append(existing).append("개가 있음 (list_findings). 처음부터 다시 하려면 clear_findings\n");
            }
            return sb.toString();
        });
    }

    ToolDef listRepositories() {
        return new ToolDef("list_repositories", "불러온 저장소 목록", "이 서버가 불러온 저장소 목록.",
                schema(props(), List.of()), true, false, args -> {
            if (registry.all().isEmpty()) {
                return "불러온 저장소 없음. load_repository 로 불러올 것";
            }
            return registry.all().stream()
                    .map(r -> r.id() + " · " + r.origin() + " · 위험 지점 " + r.graph().stats().sinks()
                            + " · 발견 " + findings.list(r.id()).size())
                    .collect(Collectors.joining("\n"));
        });
    }

    // ---- 코드 그래프 ----

    ToolDef listSinkPaths() {
        return new ToolDef("list_sink_paths", "진입점 → 위험 지점 경로",
                "외부 요청이 들어오는 진입점(HTTP API)에서 위험 지점(SQL 실행, 명령 실행, 파일 접근 등)까지 이어지는 호출 경로. "
                        + "같은 (진입점, 위험 지점) 쌍은 가장 짧은 경로 하나만, 짧은 순으로 돌려준다. 조사할 대상을 고르는 데 쓴다. "
                        + "경로는 정적 분석 결과라 틀릴 수 있으니 실제 코드로 확인해야 한다.",
                schema(props(
                        "repo", REPO,
                        "max_depth", integer("최대 호출 깊이 (기본 12, 최대 30)"),
                        "limit", integer("최대 경로 수 (기본 50, 최대 300)")), List.of("repo")),
                true, false, args -> {
            CodeGraph graph = repo(args).graph();
            List<SinkPath> paths = graph.sinkPaths(args.integer("max_depth", 12, 1, 30), args.integer("limit", 50, 1, 300));
            if (paths.isEmpty()) {
                return "진입점에서 위험 지점까지 가는 경로가 없음";
            }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < paths.size(); i++) {
                SinkPath p = paths.get(i);
                sb.append(i + 1).append(". ").append(entryLabel(p.entryPoint())).append("  →  ")
                        .append(sinkLabel(p.sink())).append('\n');
                sb.append("   경로: ").append(p.path().stream()
                        .filter(n -> n.kind() == CodeNodeKind.METHOD)
                        .map(n -> shortName(n.qualifiedName()) + "(#" + n.id() + ")")
                        .collect(Collectors.joining(" › "))).append('\n');
                sb.append("   위험 지점 위치: ").append(location(p.sink())).append(" · 코드: ").append(p.sink().prop("snippet")).append('\n');
            }
            return sb.toString();
        });
    }

    ToolDef listEntryPoints() {
        return new ToolDef("list_entry_points", "진입점 목록", "Spring MVC 컨트롤러에서 찾은 HTTP 진입점 목록.",
                schema(props("repo", REPO), List.of("repo")), true, false, args -> {
            List<Node> entries = repo(args).graph().nodes(CodeNodeKind.ENTRY_POINT);
            return entries.isEmpty() ? "진입점 없음" : entries.stream()
                    .map(n -> "#" + n.id() + " " + entryLabel(n) + " · " + shortName(n.prop("handler")) + " · " + location(n))
                    .collect(Collectors.joining("\n"));
        });
    }

    ToolDef listSinks() {
        return new ToolDef("list_sinks", "위험 지점 목록",
                "위험한 API 를 호출하는 위치 목록. 분류: SQL, COMMAND, PATH, DESERIALIZATION, SSRF, CODE_INJECTION, "
                        + "EXPRESSION_INJECTION, JNDI, OPEN_REDIRECT. 진입점에서 닿지 않는 위험 지점도 포함한다.",
                schema(props("repo", REPO, "category", string("분류로 거르기 (예: SQL)")), List.of("repo")),
                true, false, args -> {
            String category = args.optionalString("category").map(c -> c.toUpperCase(Locale.ROOT)).orElse(null);
            List<Node> sinks = repo(args).graph().nodes(CodeNodeKind.SINK).stream()
                    .filter(n -> category == null || category.equals(n.prop("category")))
                    .toList();
            return sinks.isEmpty() ? "위험 지점 없음" : sinks.stream()
                    .map(n -> "#" + n.id() + " " + sinkLabel(n) + " · " + shortName(n.prop("method")) + " · " + location(n)
                            + "\n    " + n.prop("snippet"))
                    .collect(Collectors.joining("\n"));
        });
    }

    ToolDef findCodeNodes() {
        return new ToolDef("find_code_nodes", "코드 노드 찾기",
                "이름으로 클래스·메서드·진입점·위험 지점을 찾는다 (대소문자 무시, 부분 일치). "
                        + "메서드 이름은 'Class#method(ParamType)' 형식이다.",
                schema(props(
                        "repo", REPO,
                        "query", string("찾을 이름 일부 (예: UserServiceImpl#findByName)"),
                        "kind", enumOf("노드 종류로 거르기", List.of("CLASS", "METHOD", "ENTRY_POINT", "SINK"))),
                        List.of("repo", "query")),
                true, false, args -> {
            CodeNodeKind kind = args.optionalString("kind").map(k -> CodeNodeKind.valueOf(k.toUpperCase(Locale.ROOT))).orElse(null);
            List<Node> found = repo(args).graph().find(args.string("query"), kind).stream()
                    .filter(n -> n.kind() != CodeNodeKind.FILE)
                    .limit(30)
                    .toList();
            return found.isEmpty() ? "찾지 못함" : found.stream().map(CodeAgentTools::nodeLine).collect(Collectors.joining("\n"));
        });
    }

    ToolDef getCallers() {
        return new ToolDef("get_callers", "호출하는 쪽",
                "이 메서드를 호출하는 메서드와 진입점. 인터페이스(상위 타입) 메서드를 통한 호출도 포함한다.",
                schema(props("repo", REPO, "node", string("노드 번호(예: 12) 또는 이름 (예: UserServiceImpl#findByName)")),
                        List.of("repo", "node")),
                true, false, args -> {
            CodeGraph graph = repo(args).graph();
            Node node = resolveNode(graph, args.string("node"));
            List<Node> callers = graph.callers(node.id());
            return nodeLine(node) + "\n를 호출하는 쪽:\n"
                    + (callers.isEmpty() ? "  (없음)" : callers.stream().map(n -> "  " + nodeLine(n)).collect(Collectors.joining("\n")));
        });
    }

    ToolDef getCallees() {
        return new ToolDef("get_callees", "호출되는 쪽",
                "이 메서드가 호출하는 프로젝트 메서드와 위험 지점. 인터페이스 메서드면 구현 메서드도 포함한다. "
                        + "라이브러리 호출 중 위험 지점이 아닌 것은 나오지 않는다.",
                schema(props("repo", REPO, "node", string("노드 번호 또는 이름")), List.of("repo", "node")),
                true, false, args -> {
            CodeGraph graph = repo(args).graph();
            Node node = resolveNode(graph, args.string("node"));
            List<Node> callees = graph.callees(node.id());
            return nodeLine(node) + "\n가 호출하는 쪽:\n"
                    + (callees.isEmpty() ? "  (없음)" : callees.stream().map(n -> "  " + nodeLine(n)).collect(Collectors.joining("\n")));
        });
    }

    // ---- 파일 ----

    ToolDef readFile() {
        return new ToolDef("read_file", "파일 읽기",
                "저장소의 파일을 줄 번호와 함께 읽는다. 한 번에 최대 400줄. 판단은 반드시 실제 코드를 읽고 한다.",
                schema(props(
                        "repo", REPO,
                        "path", string("저장소 루트 기준 경로 (예: src/main/java/com/example/UserService.java)"),
                        "start_line", integer("시작 줄 (기본 1)"),
                        "end_line", integer("끝 줄 (기본 시작 줄 + 199)")), List.of("repo", "path")),
                true, false, args -> {
            int start = args.integer("start_line", 1, 1, Integer.MAX_VALUE);
            int end = args.integer("end_line", start + 199, start, Integer.MAX_VALUE);
            return RepoFiles.read(repo(args).root(), args.string("path"), start, end);
        });
    }

    ToolDef grepCode() {
        return new ToolDef("grep_code", "코드 검색",
                "정규식(Java 문법)과 일치하는 줄을 '경로:줄: 내용' 으로 찾는다. 최대 80개. 입력 검증(@Valid), "
                        + "보안 설정(SecurityFilterChain), 필터·인터셉터 같은 방어 장치를 찾는 데 쓴다.",
                schema(props(
                        "repo", REPO,
                        "pattern", string("Java 정규식 (예: @Valid|@Pattern|SecurityFilterChain)"),
                        "file_glob", string("대상 파일 glob, 저장소 루트 기준 (기본 **.java, 예: **.yml, src/main/resources/**)")),
                        List.of("repo", "pattern")),
                true, false, args -> RepoFiles.grep(repo(args).root(), args.string("pattern"),
                args.optionalString("file_glob").orElse("**.java")));
    }

    // ---- 발견 ----

    ToolDef recordFinding() {
        Map<String, Object> evidenceItem = Map.of("type", "object",
                "properties", Map.of(
                        "file", string("저장소 루트 기준 파일 경로"),
                        "line", integer("줄 번호"),
                        "note", string("이 줄이 왜 근거인지")),
                "required", List.of("file", "line", "note"));
        return new ToolDef("record_finding", "발견 기록",
                "공격 가능한 취약점을 발견으로 기록한다 (검증 대기 상태). 외부 입력이 검증·이스케이프 없이 위험 지점까지 "
                        + "도달하는 것을 코드로 직접 확인했을 때만 쓴다. 막는 장치가 있거나 확신이 없으면 기록하지 않는다. "
                        + "기록한 발견은 submit_verdict 로 따로 검증한다.",
                schema(props(
                        "repo", REPO,
                        "title", string("취약점 제목 (예: 사용자 검색 API의 SQL 인젝션)"),
                        "cwe", string("CWE 번호 (예: CWE-89)"),
                        "severity", enumOf("심각도", SEVERITIES),
                        "confidence", enumOf("공격 가능하다는 확신", CONFIDENCES),
                        "description", string("입력이 어디서 들어와 어떤 경로로 위험 지점에 닿는지"),
                        "exploit_scenario", string("구체적인 공격 요청 예시"),
                        "evidence", Map.of("type", "array", "items", evidenceItem, "description", "근거 코드 위치 (1개 이상)"),
                        "entry_point", string("진입점 (예: GET /api/users/search)"),
                        "sink", string("위험 지점 API (예: JdbcTemplate.queryForList)")),
                        List.of("repo", "title", "cwe", "severity", "confidence", "description", "evidence")),
                false, false, args -> {
            LoadedRepository repo = repo(args);
            List<Evidence> evidence = new ArrayList<>();
            for (Map<String, Object> e : args.objectList("evidence")) {
                Args item = new Args(e);
                String file = item.string("file");
                RepoFiles.resolve(repo.root(), file); // 저장소 안 경로인지 확인
                evidence.add(new Evidence(file.replace('\\', '/'), item.integer("line", 1, 1, Integer.MAX_VALUE), item.string("note")));
            }
            if (evidence.isEmpty()) {
                throw new ToolException("evidence 에 근거 코드 위치가 하나 이상 있어야 함");
            }
            Finding finding = findings.add(repo.id(), new Finding(null, args.string("title"), args.string("cwe").toUpperCase(Locale.ROOT),
                    args.oneOf("severity", Set.copyOf(SEVERITIES)), args.oneOf("confidence", Set.copyOf(CONFIDENCES)),
                    args.string("description"), args.optionalString("exploit_scenario").orElse(null), evidence,
                    args.optionalString("entry_point").orElse(null), args.optionalString("sink").orElse(null),
                    Status.OPEN, null, null));
            return "발견 " + finding.id() + " 기록함 (검증 대기). 조사를 마친 뒤 반대 입장에서 다시 확인하고 submit_verdict 로 판정할 것";
        });
    }

    ToolDef submitVerdict() {
        return new ToolDef("submit_verdict", "발견 판정",
                "발견을 다시 검증한 결과를 기록한다. 보고서를 그대로 믿지 말고 코드를 직접 다시 읽은 뒤 판정한다. "
                        + "confirmed: 외부 입력으로 실제 공격 가능함을 확인. rejected: 방어 장치가 막거나 입력이 외부에서 오지 않음(오탐). "
                        + "uncertain: 판단에 필요한 코드가 저장소에 없는 등 근거 부족.",
                schema(props(
                        "repo", REPO,
                        "finding_id", string("발견 id (예: F1)"),
                        "verdict", enumOf("판정", List.of("confirmed", "rejected", "uncertain")),
                        "reasoning", string("판정 근거 (파일:줄 포함)"),
                        "blocking_controls", string("확인한 방어 장치와 그것이 공격을 막는지"),
                        "severity", enumOf("검증 후 다시 매긴 심각도 (바꿀 때만)", SEVERITIES)),
                        List.of("repo", "finding_id", "verdict", "reasoning")),
                false, false, args -> {
            Status status = VERDICTS.get(args.oneOf("verdict", VERDICTS.keySet()));
            Finding f = findings.verdict(repo(args).id(), args.string("finding_id"), status, args.string("reasoning"),
                    args.optionalString("blocking_controls").orElse(null),
                    args.optionalOneOf("severity", Set.copyOf(SEVERITIES)).orElse(null));
            return f.id() + " 판정 기록함: " + Reports.label(f.status()) + " (심각도 " + f.effectiveSeverity() + ")";
        });
    }

    ToolDef listFindings() {
        return new ToolDef("list_findings", "발견 목록",
                "기록한 발견 목록. 확정 → 검증 대기 → 판단 불가 → 기각 순, 같은 판정 안에서는 심각도 순.",
                schema(props(
                        "repo", REPO,
                        "status", enumOf("판정으로 거르기", List.of("OPEN", "CONFIRMED", "REJECTED", "UNCERTAIN")),
                        "detail", Map.of("type", "boolean", "description", "설명·근거·검증 내용까지 보여줄지 (기본 false)")),
                        List.of("repo")),
                true, false, args -> {
            LoadedRepository repo = repo(args);
            String status = args.optionalString("status").map(s -> s.toUpperCase(Locale.ROOT)).orElse(null);
            List<Finding> list = Reports.sorted(findings.list(repo.id())).stream()
                    .filter(f -> status == null || f.status().name().equals(status))
                    .toList();
            if (list.isEmpty()) {
                return "발견 없음";
            }
            if (Boolean.parseBoolean(args.optionalString("detail").orElse("false"))) {
                return Reports.markdown(repo, list, true);
            }
            return list.stream()
                    .map(f -> f.id() + " [" + Reports.label(f.status()) + "] " + f.effectiveSeverity() + " " + f.cwe() + " " + f.title()
                            + (f.entryPoint() == null ? "" : " · " + f.entryPoint()))
                    .collect(Collectors.joining("\n"));
        });
    }

    ToolDef exportReport() {
        return new ToolDef("export_report", "보고서 내보내기",
                "발견을 보고서 파일로 저장하고 경로를 돌려준다. markdown 은 내용도 함께 돌려준다. "
                        + "sarif 는 GitHub 코드 스캐닝 등에 올릴 수 있는 SARIF 2.1.0 (기각된 발견 제외).",
                schema(props(
                        "repo", REPO,
                        "format", enumOf("형식 (기본 markdown)", List.of("markdown", "sarif")),
                        "include_rejected", Map.of("type", "boolean", "description", "markdown 에 기각된 발견도 넣을지 (기본 false)")),
                        List.of("repo")),
                false, false, args -> {
            LoadedRepository repo = repo(args);
            String format = args.optionalOneOf("format", Set.of("markdown", "sarif")).orElse("markdown");
            List<Finding> list = findings.list(repo.id());
            String content = format.equals("sarif")
                    ? Reports.sarif(repo, list)
                    : Reports.markdown(repo, list, Boolean.parseBoolean(args.optionalString("include_rejected").orElse("false")));
            String stamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss"));
            Path file = workspace.reports().resolve(repo.id() + "-" + stamp + (format.equals("sarif") ? ".sarif" : ".md"));
            try {
                Files.createDirectories(file.getParent());
                Files.writeString(file, content, StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            return "저장함: " + file.toAbsolutePath() + (format.equals("sarif") ? "" : "\n\n" + content);
        });
    }

    ToolDef clearFindings() {
        return new ToolDef("clear_findings", "발견 모두 지우기",
                "이 저장소의 발견을 모두 지운다. 처음부터 다시 분석할 때만, 사용자가 원할 때 쓴다.",
                schema(props("repo", REPO), List.of("repo")), false, false,
                args -> "발견 " + findings.clear(repo(args).id()) + "개를 지움");
    }

    // ---- 헬퍼 ----

    private LoadedRepository repo(Args args) {
        return registry.get(args.string("repo"));
    }

    static Node resolveNode(CodeGraph graph, String ref) {
        String r = ref.strip().replaceFirst("^#", "");
        if (r.matches("\\d+")) {
            return graph.node(Integer.parseInt(r)).orElseThrow(() -> new ToolException("노드 없음: #" + r));
        }
        List<Node> found = graph.find(r, null).stream()
                .filter(n -> n.kind() == CodeNodeKind.METHOD || n.kind() == CodeNodeKind.ENTRY_POINT || n.kind() == CodeNodeKind.SINK)
                .toList();
        if (found.isEmpty()) {
            throw new ToolException("찾지 못함: " + ref + ". find_code_nodes 로 이름을 확인할 것");
        }
        List<Node> exact = found.stream().filter(n -> shortName(n.qualifiedName()).toLowerCase(Locale.ROOT)
                .startsWith(r.toLowerCase(Locale.ROOT)) || n.qualifiedName().equalsIgnoreCase(r)).toList();
        List<Node> candidates = exact.isEmpty() ? found : exact;
        // 메서드 이름은 그 안의 위험 지점 이름에도 들어가므로, 메서드가 하나뿐이면 메서드를 고른다
        List<Node> methods = candidates.stream().filter(n -> n.kind() == CodeNodeKind.METHOD).toList();
        if (methods.size() == 1) {
            return methods.get(0);
        }
        if (candidates.size() > 1 && !candidates.get(0).qualifiedName().equalsIgnoreCase(r)) {
            throw new ToolException("여러 개가 일치함. 번호로 다시 지정할 것:\n" + candidates.stream().limit(10)
                    .map(CodeAgentTools::nodeLine).collect(Collectors.joining("\n")));
        }
        return candidates.get(0);
    }

    static String nodeLine(Node n) {
        String name = switch (n.kind()) {
            case ENTRY_POINT -> entryLabel(n) + " → " + n.prop("handler");
            case SINK -> sinkLabel(n) + " (" + n.prop("method") + ")";
            default -> n.qualifiedName();
        };
        String loc = location(n);
        return "#" + n.id() + " " + n.kind() + " " + name + (loc.isEmpty() ? "" : "  [" + loc + "]");
    }

    static String entryLabel(Node n) {
        return n.prop("httpMethod") + " " + n.prop("path");
    }

    static String sinkLabel(Node n) {
        return "[" + n.prop("category") + " " + n.prop("cwe") + "] " + n.prop("api");
    }

    static String location(Node n) {
        if (n.filePath() == null) {
            return "";
        }
        return n.line() == null ? n.filePath() : n.filePath() + ":" + n.line();
    }

    /** com.example.UserServiceImpl#search(String) → UserServiceImpl#search(String) */
    static String shortName(String qualifiedName) {
        if (qualifiedName == null) {
            return "";
        }
        int hash = qualifiedName.indexOf('#');
        String owner = hash < 0 ? qualifiedName : qualifiedName.substring(0, hash);
        String simple = owner.substring(owner.lastIndexOf('.') + 1);
        return hash < 0 ? simple : simple + qualifiedName.substring(hash);
    }

    /** 순서를 지키는 properties 맵 (이름, 스키마, 이름, 스키마, ...) */
    @SuppressWarnings("unchecked")
    static Map<String, Map<String, Object>> props(Object... pairs) {
        Map<String, Map<String, Object>> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            map.put((String) pairs[i], (Map<String, Object>) pairs[i + 1]);
        }
        return map;
    }
}
