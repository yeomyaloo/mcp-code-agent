package com.codeagent.mcp.tools;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 도구 인자를 꺼내고 검사한다. 잘못된 입력은 ToolException 으로 알려서 Claude 가 고쳐서 다시 부르게 한다.
 */
public record Args(Map<String, Object> values) {

    public Args {
        values = values == null ? Map.of() : values;
    }

    public String string(String name) {
        return optionalString(name).orElseThrow(() -> new ToolException(name + " 이(가) 필요함"));
    }

    public Optional<String> optionalString(String name) {
        Object value = values.get(name);
        if (value == null) {
            return Optional.empty();
        }
        String s = value.toString().strip();
        return s.isEmpty() ? Optional.empty() : Optional.of(s);
    }

    public int integer(String name, int defaultValue, int min, int max) {
        Object value = values.get(name);
        if (value == null) {
            return defaultValue;
        }
        int n;
        if (value instanceof Number number) {
            n = number.intValue();
        } else {
            try {
                n = Integer.parseInt(value.toString().strip());
            } catch (NumberFormatException e) {
                throw new ToolException(name + " 은(는) 정수여야 함: " + value);
            }
        }
        if (n < min || n > max) {
            throw new ToolException(name + " 은(는) " + min + " ~ " + max + " 사이여야 함: " + n);
        }
        return n;
    }

    public String oneOf(String name, Set<String> allowed) {
        String value = string(name).toLowerCase();
        if (!allowed.contains(value)) {
            throw new ToolException(name + " 은(는) " + allowed + " 중 하나여야 함: " + value);
        }
        return value;
    }

    public Optional<String> optionalOneOf(String name, Set<String> allowed) {
        return optionalString(name).map(v -> {
            if (!allowed.contains(v.toLowerCase())) {
                throw new ToolException(name + " 은(는) " + allowed + " 중 하나여야 함: " + v);
            }
            return v.toLowerCase();
        });
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> objectList(String name) {
        Object value = values.get(name);
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list) || !list.stream().allMatch(v -> v instanceof Map)) {
            throw new ToolException(name + " 은(는) 객체 배열이어야 함");
        }
        return (List<Map<String, Object>>) value;
    }
}
