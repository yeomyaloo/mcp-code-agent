package com.codeagent.mcp.findings;

import com.codeagent.mcp.findings.Finding.Status;
import com.codeagent.mcp.findings.Finding.Verification;
import com.codeagent.mcp.tools.ToolException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 저장소별 발견 목록. 바뀔 때마다 {home}/findings/{저장소}.json 에 저장해서 서버를 다시 켜도 남는다.
 */
public class FindingStore {

    private static final TypeReference<List<Finding>> LIST = new TypeReference<>() {
    };

    private final Path dir;
    private final JsonMapper json = JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
    private final Map<String, List<Finding>> byRepository = new HashMap<>();

    public FindingStore(Path dir) {
        this.dir = dir;
    }

    public synchronized List<Finding> list(String repositoryId) {
        return List.copyOf(load(repositoryId));
    }

    public synchronized Finding add(String repositoryId, Finding draft) {
        List<Finding> findings = load(repositoryId);
        Finding finding = new Finding("F" + (findings.size() + 1), draft.title(), draft.cwe(), draft.severity(),
                draft.confidence(), draft.description(), draft.exploitScenario(), List.copyOf(draft.evidence()),
                draft.entryPoint(), draft.sink(), Status.OPEN, null, OffsetDateTime.now().toString());
        findings.add(finding);
        save(repositoryId, findings);
        return finding;
    }

    /** 판정을 기록한다. 이미 판정된 발견도 덮어쓴다 (다시 검증한 경우) */
    public synchronized Finding verdict(String repositoryId, String findingId, Status status, String reasoning,
                                        String blockingControls, String severity) {
        List<Finding> findings = load(repositoryId);
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            if (finding.id().equalsIgnoreCase(findingId)) {
                Finding updated = finding.withVerdict(status, new Verification(status.name().toLowerCase(), reasoning,
                        blockingControls, severity, OffsetDateTime.now().toString()));
                findings.set(i, updated);
                save(repositoryId, findings);
                return updated;
            }
        }
        throw new ToolException("발견 없음: " + findingId + " (있는 발견: "
                + String.join(", ", findings.stream().map(Finding::id).toList()) + ")");
    }

    /** 이 저장소의 발견을 모두 지운다 (처음부터 다시 분석할 때) */
    public synchronized int clear(String repositoryId) {
        int count = load(repositoryId).size();
        byRepository.put(repositoryId, new ArrayList<>());
        save(repositoryId, List.of());
        return count;
    }

    private List<Finding> load(String repositoryId) {
        return byRepository.computeIfAbsent(repositoryId, id -> {
            Path file = file(id);
            if (!Files.exists(file)) {
                return new ArrayList<>();
            }
            return new ArrayList<>(json.readValue(file.toFile(), LIST));
        });
    }

    private void save(String repositoryId, List<Finding> findings) {
        try {
            Files.createDirectories(dir);
            json.writeValue(file(repositoryId).toFile(), findings);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private Path file(String repositoryId) {
        return dir.resolve(repositoryId + ".json");
    }
}
