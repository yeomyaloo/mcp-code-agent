package com.codeagent.mcp.workspace;

import com.codeagent.mcp.codegraph.CodeGraph;
import com.codeagent.mcp.source.GitCloner;
import com.codeagent.mcp.source.GitCloner.CloneResult;
import com.codeagent.mcp.source.GitUrlPolicy;
import com.codeagent.mcp.tools.ToolException;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * 이 서버 프로세스가 불러온 저장소 목록. 코드 그래프는 메모리에만 있고, 서버를 다시 켜면 다시 불러온다.
 */
public class RepositoryRegistry {

    private final Workspace workspace;
    private final GitUrlPolicy gitUrlPolicy;
    private final GitCloner gitCloner;
    private final Map<String, LoadedRepository> repositories = new LinkedHashMap<>();

    public RepositoryRegistry(Workspace workspace) {
        this(workspace, new GitUrlPolicy(workspace.gitHosts()));
    }

    public RepositoryRegistry(Workspace workspace, GitUrlPolicy gitUrlPolicy) {
        this.workspace = workspace;
        this.gitUrlPolicy = gitUrlPolicy;
        this.gitCloner = new GitCloner(workspace.cloneTimeoutSeconds(), workspace.maxRepoBytes());
    }

    /** 로컬 폴더를 불러온다. 같은 이름이 있으면 다시 파싱해서 바꾼다 */
    public synchronized LoadedRepository loadLocal(String path, String name) {
        Path root = Path.of(path).toAbsolutePath().normalize();
        if (!Files.isDirectory(root)) {
            throw new ToolException("폴더가 아님: " + root);
        }
        String id = idFor(name != null ? name : root.getFileName().toString());
        return put(new LoadedRepository(id, root, null, null, null, CodeGraph.build(root), OffsetDateTime.now()));
    }

    /** 공개 Git 저장소를 얕게 클론해서 불러온다. 이미 받은 저장소면 최신 커밋으로 다시 받는다 */
    public synchronized LoadedRepository loadGit(String gitUrl, String branch, String name) {
        String url;
        try {
            url = gitUrlPolicy.validate(gitUrl);
        } catch (IllegalArgumentException e) {
            throw new ToolException(e.getMessage());
        }
        String id = idFor(name != null ? name : GitUrlPolicy.repoName(url));
        Path target = workspace.repos().resolve(id);
        GitCloner.deleteQuietly(target);
        try {
            Files.createDirectories(target.getParent());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        CloneResult clone;
        try {
            clone = gitCloner.cloneInto(url, branch, target);
        } catch (IllegalArgumentException e) {
            throw new ToolException(e.getMessage());
        }
        return put(new LoadedRepository(id, target, url, clone.branch(), clone.commitSha(), CodeGraph.build(target),
                OffsetDateTime.now()));
    }

    public synchronized LoadedRepository get(String id) {
        LoadedRepository repository = repositories.get(id);
        if (repository == null) {
            throw new ToolException("불러온 저장소가 아님: " + id + ". load_repository 를 먼저 호출할 것"
                    + (repositories.isEmpty() ? "" : " (불러온 저장소: " + String.join(", ", repositories.keySet()) + ")"));
        }
        return repository;
    }

    public synchronized Collection<LoadedRepository> all() {
        return repositories.values().stream().toList();
    }

    private LoadedRepository put(LoadedRepository repository) {
        repositories.put(repository.id(), repository);
        return repository;
    }

    /** 도구 인자로 쓰기 쉬운 이름으로 바꾼다 (영문 소문자, 숫자, . _ -) */
    static String idFor(String name) {
        String id = name.strip().toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]+", "-").replaceAll("^-+|-+$", "");
        if (id.isEmpty() || id.equals(".") || id.equals("..")) {
            throw new ToolException("저장소 이름으로 쓸 수 없음: " + name);
        }
        return id;
    }
}
