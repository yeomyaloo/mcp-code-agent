package com.codeagent.mcp.tools;

/**
 * 도구 입력이 잘못됐거나 요청을 처리할 수 없을 때. 메시지가 그대로 Claude 에게 오류로 전달된다.
 */
public class ToolException extends RuntimeException {

    public ToolException(String message) {
        super(message);
    }
}
