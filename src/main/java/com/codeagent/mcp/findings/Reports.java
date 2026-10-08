package com.codeagent.mcp.findings;

import com.codeagent.mcp.findings.Finding.Evidence;
import com.codeagent.mcp.findings.Finding.Status;
import com.codeagent.mcp.workspace.LoadedRepository;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 발견 목록을 Markdown, SARIF 2.1.0 으로 쓴다.
 */
public final class Reports {

    private static final List<String> SEVERITY_ORDER = List.of("critical", "high", "medium", "low", "info");
    private static final List<Status> STATUS_ORDER = List.of(Status.CONFIRMED, Status.OPEN, Status.UNCERTAIN, Status.REJECTED);

    private Reports() {
    }

    /** 확정 → 검증 대기 → 판단 불가 → 기각, 같은 판정 안에서는 심각도 순 */
    public static List<Finding> sorted(List<Finding> findings) {
        return findings.stream()
                .sorted(Comparator.comparing((Finding f) -> STATUS_ORDER.indexOf(f.status()))
                        .thenComparing(f -> rank(f.effectiveSeverity())))
                .toList();
    }

    public static String markdown(LoadedRepository repository, List<Finding> findings, boolean includeRejected) {
        List<Finding> shown = sorted(findings).stream()
                .filter(f -> includeRejected || f.status() != Status.REJECTED)
                .toList();
        Map<Status, Long> counts = new LinkedHashMap<>();
        STATUS_ORDER.forEach(s -> counts.put(s, findings.stream().filter(f -> f.status() == s).count()));

        StringBuilder md = new StringBuilder();
        md.append("# 보안 분석 보고서: ").append(repository.id()).append("\n\n");
        md.append("- 대상: ").append(repository.origin()).append('\n');
        md.append("- 확정 ").append(counts.get(Status.CONFIRMED))
                .append(" · 검증 대기 ").append(counts.get(Status.OPEN))
                .append(" · 판단 불가 ").append(counts.get(Status.UNCERTAIN))
                .append(" · 기각(오탐) ").append(counts.get(Status.REJECTED)).append("\n\n");
        if (shown.isEmpty()) {
            md.append("보고할 발견이 없습니다.\n");
            return md.toString();
        }
        md.append("| ID | 판정 | 심각도 | CWE | 제목 |\n|---|---|---|---|---|\n");
        for (Finding f : shown) {
            md.append("| ").append(f.id()).append(" | ").append(label(f.status())).append(" | ")
                    .append(nullToDash(f.effectiveSeverity())).append(" | ").append(nullToDash(f.cwe())).append(" | ")
                    .append(f.title().replace("|", "\\|")).append(" |\n");
        }
        for (Finding f : shown) {
            md.append("\n## ").append(f.id()).append(". ").append(f.title()).append("\n\n");
            md.append("- 판정: **").append(label(f.status())).append("** · 심각도: ").append(nullToDash(f.effectiveSeverity()))
                    .append(" · ").append(nullToDash(f.cwe())).append(" · 조사 확신: ").append(nullToDash(f.confidence())).append('\n');
            if (f.entryPoint() != null || f.sink() != null) {
                md.append("- 경로: `").append(nullToDash(f.entryPoint())).append("` → `").append(nullToDash(f.sink())).append("`\n");
            }
            md.append('\n').append(f.description()).append('\n');
            if (f.exploitScenario() != null && !f.exploitScenario().isBlank()) {
                md.append("\n**공격 예시**\n\n```\n").append(f.exploitScenario().strip()).append("\n```\n");
            }
            if (!f.evidence().isEmpty()) {
                md.append("\n**근거 코드**\n\n");
                for (Evidence e : f.evidence()) {
                    md.append("- `").append(e.file()).append(':').append(e.line()).append("` ").append(e.note()).append('\n');
                }
            }
            if (f.verification() != null) {
                md.append("\n**검증**\n\n").append(f.verification().reasoning()).append('\n');
                if (f.verification().blockingControls() != null && !f.verification().blockingControls().isBlank()) {
                    md.append("\n- 확인한 방어 장치: ").append(f.verification().blockingControls()).append('\n');
                }
            }
        }
        return md.toString();
    }

    /** SARIF 2.1.0. 기각된 발견은 빼고, 검증 대기·판단 불가는 warning 으로 낮춘다 */
    public static String sarif(LoadedRepository repository, List<Finding> findings) {
        List<Map<String, Object>> rules = new ArrayList<>();
        List<Map<String, Object>> results = new ArrayList<>();
        Map<String, Integer> ruleIndex = new LinkedHashMap<>();
        for (Finding f : sorted(findings)) {
            if (f.status() == Status.REJECTED) {
                continue;
            }
            String ruleId = f.cwe() == null ? "code-agent" : f.cwe();
            ruleIndex.computeIfAbsent(ruleId, id -> {
                Map<String, Object> rule = new LinkedHashMap<>();
                rule.put("id", id);
                rule.put("name", id);
                if (id.startsWith("CWE-")) {
                    rule.put("helpUri", "https://cwe.mitre.org/data/definitions/" + id.substring(4) + ".html");
                }
                rules.add(rule);
                return rules.size() - 1;
            });
            List<Map<String, Object>> locations = f.evidence().stream().map(e -> Map.<String, Object>of(
                    "physicalLocation", Map.of(
                            "artifactLocation", Map.of("uri", e.file()),
                            "region", Map.of("startLine", Math.max(1, e.line()))),
                    "message", Map.of("text", e.note()))).toList();
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", ruleId);
            result.put("ruleIndex", ruleIndex.get(ruleId));
            result.put("level", f.status() == Status.CONFIRMED ? level(f.effectiveSeverity()) : "warning");
            result.put("message", Map.of("text", f.title() + "\n\n" + f.description()));
            result.put("locations", locations.isEmpty() ? List.of() : List.of(locations.get(0)));
            if (locations.size() > 1) {
                result.put("relatedLocations", locations.subList(1, locations.size()));
            }
            result.put("properties", Map.of(
                    "findingId", f.id(),
                    "verdict", f.status().name(),
                    "severity", nullToDash(f.effectiveSeverity())));
            results.add(result);
        }
        Map<String, Object> sarif = Map.of(
                "$schema", "https://json.schemastore.org/sarif-2.1.0.json",
                "version", "2.1.0",
                "runs", List.of(Map.of(
                        "tool", Map.of("driver", Map.of(
                                "name", "mcp-code-agent",
                                "informationUri", "https://github.com/yeomyaloo/mcp-code-agent",
                                "rules", rules)),
                        "results", results)));
        return JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build().writeValueAsString(sarif);
    }

    public static String label(Status status) {
        return switch (status) {
            case OPEN -> "검증 대기";
            case CONFIRMED -> "확정";
            case REJECTED -> "기각(오탐)";
            case UNCERTAIN -> "판단 불가";
        };
    }

    private static String level(String severity) {
        return switch (severity == null ? "" : severity) {
            case "critical", "high" -> "error";
            case "medium" -> "warning";
            default -> "note";
        };
    }

    private static int rank(String severity) {
        int i = SEVERITY_ORDER.indexOf(severity);
        return i < 0 ? SEVERITY_ORDER.size() : i;
    }

    private static String nullToDash(String s) {
        return s == null || s.isBlank() ? "-" : s;
    }
}
