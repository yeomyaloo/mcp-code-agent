package com.codeagent.mcp.tools;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Stream;

/**
 * 저장소 안의 파일만 읽는다. 저장소 밖 경로(../, 심볼릭 링크)는 막는다.
 */
public final class RepoFiles {

    static final Set<String> SKIP_DIRS = Set.of(".git", ".gradle", ".idea", "build", "target", "out", "node_modules");
    static final int MAX_LINES = 400;
    static final int MAX_MATCHES = 80;
    private static final int MAX_LINE_LENGTH = 240;

    private RepoFiles() {
    }

    static Path resolve(Path repoRoot, String relativePath) {
        Path root = repoRoot.toAbsolutePath().normalize();
        try {
            Path resolved = root.resolve(relativePath.replace('\\', '/')).normalize();
            if (!resolved.startsWith(root)) {
                throw new ToolException("저장소 밖 경로는 읽을 수 없음: " + relativePath);
            }
            if (Files.exists(resolved) && !resolved.toRealPath().startsWith(root.toRealPath())) {
                throw new ToolException("저장소 밖 경로는 읽을 수 없음: " + relativePath);
            }
            return resolved;
        } catch (InvalidPathException e) {
            throw new ToolException("잘못된 경로: " + relativePath);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** 줄 번호를 붙여 읽는다. 한 번에 최대 400줄 */
    static String read(Path repoRoot, String relativePath, int startLine, int endLine) {
        Path file = resolve(repoRoot, relativePath);
        if (!Files.isRegularFile(file)) {
            throw new ToolException("파일이 없음: " + relativePath);
        }
        List<String> lines = readLines(file);
        if (lines == null) {
            throw new ToolException("텍스트(UTF-8) 파일이 아님: " + relativePath);
        }
        if (startLine > lines.size()) {
            return "파일은 " + lines.size() + "줄뿐임";
        }
        int end = Math.min(Math.min(lines.size(), endLine), startLine + MAX_LINES - 1);
        StringBuilder sb = new StringBuilder();
        sb.append(relative(repoRoot, file)).append(" (").append(startLine).append('-').append(end)
                .append(" / 전체 ").append(lines.size()).append("줄)\n");
        for (int i = startLine; i <= end; i++) {
            sb.append(String.format("%5d | %s%n", i, lines.get(i - 1)));
        }
        if (end < Math.min(lines.size(), endLine)) {
            sb.append("... (한 번에 ").append(MAX_LINES).append("줄까지. start_line=").append(end + 1).append(" 로 이어서 읽을 것)\n");
        }
        return sb.toString();
    }

    /** 정규식과 일치하는 줄을 '경로:줄: 내용' 으로 */
    static String grep(Path repoRoot, String regex, String glob) {
        Pattern pattern;
        try {
            pattern = Pattern.compile(regex);
        } catch (PatternSyntaxException e) {
            throw new ToolException("정규식 오류: " + e.getDescription());
        }
        PathMatcher matcher = FileSystems.getDefault().getPathMatcher("glob:" + glob);
        Path root = repoRoot.toAbsolutePath().normalize();
        List<String> matches = new ArrayList<>();
        boolean truncated = false;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : (Iterable<Path>) files.filter(p -> Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS))::iterator) {
                Path rel = root.relativize(file);
                if (isSkipped(rel) || !matcher.matches(rel)) {
                    continue;
                }
                List<String> lines = readLines(file);
                if (lines == null) {
                    continue;
                }
                for (int i = 0; i < lines.size() && !truncated; i++) {
                    if (pattern.matcher(lines.get(i)).find()) {
                        if (matches.size() >= MAX_MATCHES) {
                            truncated = true;
                            break;
                        }
                        String line = lines.get(i).strip();
                        matches.add(rel.toString().replace('\\', '/') + ":" + (i + 1) + ": "
                                + (line.length() > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) + "..." : line));
                    }
                }
                if (truncated) {
                    break;
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (matches.isEmpty()) {
            return "일치하는 줄 없음";
        }
        String result = String.join("\n", matches);
        return truncated ? result + "\n... (" + MAX_MATCHES + "개에서 잘림. pattern 이나 file_glob 을 좁힐 것)" : result;
    }

    static String relative(Path repoRoot, Path file) {
        return repoRoot.toAbsolutePath().normalize().relativize(file).toString().replace('\\', '/');
    }

    private static boolean isSkipped(Path relative) {
        for (Path part : relative) {
            if (SKIP_DIRS.contains(part.toString())) {
                return true;
            }
        }
        return false;
    }

    /** @return UTF-8 텍스트가 아니면 null */
    private static List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            return null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
