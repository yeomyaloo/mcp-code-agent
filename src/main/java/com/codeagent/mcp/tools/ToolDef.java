package com.codeagent.mcp.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * MCP 도구 하나. 결과는 Claude 가 읽을 텍스트로 돌려준다.
 *
 * @param readOnly  저장소나 기록을 바꾸지 않는 도구인지 (클라이언트가 승인 없이 부르게 할 수 있다)
 * @param openWorld 외부 네트워크에 접근하는지 (Git 클론)
 */
public record ToolDef(String name, String title, String description, Map<String, Object> inputSchema,
                      boolean readOnly, boolean openWorld, Function<Args, String> handler) {

    /** JSON Schema object 를 만든다. properties 는 순서를 지킨다 */
    public static Map<String, Object> schema(Map<String, Map<String, Object>> properties, List<String> required) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");
        schema.put("properties", properties);
        schema.put("required", required);
        schema.put("additionalProperties", false);
        return schema;
    }

    public static Map<String, Object> string(String description) {
        return Map.of("type", "string", "description", description);
    }

    public static Map<String, Object> integer(String description) {
        return Map.of("type", "integer", "description", description);
    }

    public static Map<String, Object> enumOf(String description, List<String> values) {
        return Map.of("type", "string", "enum", values, "description", description);
    }
}
