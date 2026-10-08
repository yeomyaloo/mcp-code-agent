package com.codeagent.mcp.workspace;

import com.codeagent.mcp.codegraph.CodeGraph;

import java.nio.file.Path;
import java.time.OffsetDateTime;

/**
 * 분석하려고 불러온 저장소와 그 코드 그래프.
 *
 * @param id     도구에서 저장소를 가리키는 이름 (예: vulnerable-app)
 * @param gitUrl 로컬 폴더에서 불러왔으면 null
 */
public record LoadedRepository(String id, Path root, String gitUrl, String branch, String commitSha,
                               CodeGraph graph, OffsetDateTime loadedAt) {

    public String origin() {
        if (gitUrl == null) {
            return root.toString();
        }
        return gitUrl + " (" + branch + " @ " + commitSha.substring(0, Math.min(12, commitSha.length())) + ")";
    }
}
