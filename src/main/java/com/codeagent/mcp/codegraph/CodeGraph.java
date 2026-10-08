package com.codeagent.mcp.codegraph;

import com.codeagent.mcp.codegraph.CodeGraphDraft.EdgeDraft;
import com.codeagent.mcp.codegraph.CodeGraphDraft.NodeDraft;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 메모리에 올린 코드 그래프. 노드에 1부터 번호를 붙여 도구 입출력에서 짧게 가리킬 수 있게 한다.
 * (be-code-agent 는 같은 그래프를 PostgreSQL 에 저장하고 재귀 CTE 로 탐색한다)
 */
public class CodeGraph {

    /** 진입점에서 위험 지점까지 따라가는 연결선 */
    private static final Set<CodeEdgeKind> FLOW = EnumSet.of(CodeEdgeKind.ROUTES_TO, CodeEdgeKind.CALLS, CodeEdgeKind.OVERRIDDEN_BY);

    public record Node(int id, CodeNodeKind kind, String qualifiedName, String filePath, Integer line,
                       Map<String, Object> props) {

        public String prop(String name) {
            Object value = props.get(name);
            return value == null ? null : value.toString();
        }
    }

    public record Edge(int src, int dst, CodeEdgeKind kind) {
    }

    /** @param path 진입점부터 위험 지점까지 (양 끝 포함) */
    public record SinkPath(Node entryPoint, Node sink, List<Node> path) {
    }

    public record Stats(long files, long classes, long methods, long entryPoints, long sinks, long callEdges,
                        long overrideEdges, int unresolvedCalls, List<String> parseErrors) {
    }

    private final List<Node> nodes = new ArrayList<>();
    private final Map<Integer, List<Edge>> outgoing = new HashMap<>();
    private final Map<Integer, List<Edge>> incoming = new HashMap<>();
    private final Stats stats;

    private CodeGraph(CodeGraphDraft draft, List<String> parseErrors) {
        Map<String, Integer> ids = new HashMap<>();
        for (NodeDraft d : draft.nodes()) {
            Node node = new Node(nodes.size() + 1, d.kind(), d.qualifiedName(), d.filePath(), d.startLine(), d.props());
            nodes.add(node);
            ids.put(d.key(), node.id());
        }
        for (EdgeDraft e : draft.edges()) {
            Integer src = ids.get(e.srcKey());
            Integer dst = ids.get(e.dstKey());
            if (src == null || dst == null) {
                continue;
            }
            Edge edge = new Edge(src, dst, e.kind());
            outgoing.computeIfAbsent(src, k -> new ArrayList<>()).add(edge);
            incoming.computeIfAbsent(dst, k -> new ArrayList<>()).add(edge);
        }
        this.stats = new Stats(draft.count(CodeNodeKind.FILE), draft.count(CodeNodeKind.CLASS),
                draft.count(CodeNodeKind.METHOD), draft.count(CodeNodeKind.ENTRY_POINT), draft.count(CodeNodeKind.SINK),
                draft.count(CodeEdgeKind.CALLS), draft.count(CodeEdgeKind.OVERRIDDEN_BY), draft.unresolvedCalls(),
                List.copyOf(parseErrors));
    }

    /** 저장소를 파싱해서 그래프를 만든다 */
    public static CodeGraph build(java.nio.file.Path repoRoot) {
        JavaProject project = JavaProject.load(repoRoot);
        return new CodeGraph(new CodeGraphBuilder(project).build(), project.parseErrors());
    }

    public Stats stats() {
        return stats;
    }

    public Optional<Node> node(int id) {
        return id >= 1 && id <= nodes.size() ? Optional.of(nodes.get(id - 1)) : Optional.empty();
    }

    public List<Node> nodes(CodeNodeKind kind) {
        return nodes.stream().filter(n -> n.kind() == kind).toList();
    }

    /**
     * 이름에 query 가 들어간 노드 (대소문자 무시). 정확히 같은 이름, 짧은 이름 순.
     */
    public List<Node> find(String query, CodeNodeKind kind) {
        String q = query.toLowerCase(Locale.ROOT);
        return nodes.stream()
                .filter(n -> kind == null || n.kind() == kind)
                .filter(n -> n.qualifiedName().toLowerCase(Locale.ROOT).contains(q))
                .sorted(Comparator.comparing((Node n) -> !n.qualifiedName().equalsIgnoreCase(query))
                        .thenComparing(n -> n.qualifiedName().length()))
                .toList();
    }

    /** 이 노드를 호출하는 쪽 (진입점 라우팅, 상위 타입 메서드 포함) */
    public List<Node> callers(int id) {
        return neighbours(incoming.getOrDefault(id, List.of()), true);
    }

    /** 이 노드가 호출하는 쪽 (구현 메서드, 위험 지점 포함) */
    public List<Node> callees(int id) {
        return neighbours(outgoing.getOrDefault(id, List.of()), false);
    }

    private List<Node> neighbours(Collection<Edge> edges, boolean useSrc) {
        return edges.stream()
                .filter(e -> FLOW.contains(e.kind()))
                .map(e -> nodes.get((useSrc ? e.src() : e.dst()) - 1))
                .distinct()
                .sorted(Comparator.comparing(Node::qualifiedName))
                .toList();
    }

    /**
     * 진입점에서 위험 지점까지의 호출 경로. 같은 (진입점, 위험 지점) 쌍은 가장 짧은 경로 하나만 돌려준다.
     * 진입점마다 BFS 를 하므로 처음 닿은 경로가 가장 짧다.
     */
    public List<SinkPath> sinkPaths(int maxDepth, int limit) {
        List<SinkPath> result = new ArrayList<>();
        for (Node entry : nodes(CodeNodeKind.ENTRY_POINT)) {
            Map<Integer, Integer> parent = new LinkedHashMap<>();
            Map<Integer, Integer> depth = new HashMap<>();
            Deque<Integer> queue = new ArrayDeque<>();
            parent.put(entry.id(), 0);
            depth.put(entry.id(), 0);
            queue.add(entry.id());
            while (!queue.isEmpty()) {
                int current = queue.poll();
                Node node = nodes.get(current - 1);
                if (node.kind() == CodeNodeKind.SINK) {
                    result.add(new SinkPath(entry, node, pathTo(current, parent)));
                    continue;
                }
                if (depth.get(current) >= maxDepth) {
                    continue;
                }
                for (Edge edge : outgoing.getOrDefault(current, List.of())) {
                    if (FLOW.contains(edge.kind()) && !parent.containsKey(edge.dst())) {
                        parent.put(edge.dst(), current);
                        depth.put(edge.dst(), depth.get(current) + 1);
                        queue.add(edge.dst());
                    }
                }
            }
        }
        result.sort(Comparator.comparingInt((SinkPath p) -> p.path().size())
                .thenComparing(p -> p.entryPoint().id())
                .thenComparing(p -> p.sink().id()));
        return result.size() > limit ? List.copyOf(result.subList(0, limit)) : result;
    }

    private List<Node> pathTo(int last, Map<Integer, Integer> parent) {
        List<Node> path = new ArrayList<>();
        for (int id = last; id != 0; id = parent.get(id)) {
            path.add(0, nodes.get(id - 1));
        }
        return path;
    }
}
