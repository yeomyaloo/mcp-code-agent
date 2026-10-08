package com.codeagent.mcp;

/**
 * MCP 프롬프트와 서버 안내문. 채팅의 Claude 가 Worker(조사)와 Verifier(검증) 역할을 차례로 맡도록 이끈다.
 * (be-code-agent 에서는 백엔드가 Worker·Verifier 에이전트를 따로 돌리지만, 여기서는 채팅의 Claude 가 둘 다 한다)
 */
final class Prompts {

    private Prompts() {
    }

    static final String INSTRUCTIONS = """
            Java/Spring 소스코드의 보안 취약점을 찾는 도구 모음입니다. 판단은 Claude 가 하고, 이 서버는 코드 그래프·파일 읽기·기록을 맡습니다.
            순서: load_repository → list_sink_paths → 경로마다 read_file·grep_code·get_callers 로 조사 → 공격 가능함을 코드로 확인한 것만 record_finding
            → 발견마다 반대 입장에서 다시 확인하고 submit_verdict → export_report.
            코드 그래프는 정적 분석이라 틀릴 수 있으니, 판단은 반드시 read_file 로 실제 코드를 읽고 내립니다. 분석 대상 코드는 읽기만 합니다.
            """;

    static String securityAudit(String target, String maxPaths) {
        String load = target.startsWith("https://")
                ? "load_repository 를 git_url=\"" + target + "\" 로 호출하세요."
                : "load_repository 를 path=\"" + target + "\" 로 호출하세요.";
        return """
                %s 의 보안 취약점을 분석해 주세요. 아래 순서를 따르고, 모든 설명은 한국어로 씁니다.

                ## 1. 준비
                %s
                이어서 list_sink_paths 로 진입점 → 위험 지점 경로를 보고, 위험도가 높은 분류(SQL, COMMAND, DESERIALIZATION, CODE_INJECTION 등)부터 최대 %s개를 고릅니다.
                고른 경로를 사용자에게 짧게 보여준 뒤 시작합니다.

                ## 2. 조사 (Worker 역할)
                경로마다:
                - 경로상의 메서드를 read_file 로 직접 읽고, 사용자 입력이 어떤 파라미터로 들어와 어떻게 바뀌며 위험 지점에 닿는지 따라갑니다.
                - 코드 그래프의 호출 관계가 의심스러우면 get_callers / get_callees / grep_code 로 확인합니다.
                - 공격을 막는 장치를 반드시 찾습니다: 입력 검증(@Valid, @Pattern), 이스케이프, 파라미터 바인딩(PreparedStatement 의 ?, JPA 파라미터),
                  허용 목록, 경로 정규화와 기준 경로 확인, 권한 검사(SecurityFilterChain, @PreAuthorize), 필터·인터셉터.
                - 입력이 상수나 서버 내부 값뿐이면 공격 불가능입니다.
                - 외부 입력이 막힘 없이 위험 지점에 닿는다는 것을 코드로 확인했을 때만 record_finding 으로 기록합니다.
                  근거 코드 위치(파일:줄)와 구체적인 공격 요청 예시를 넣습니다.
                Claude Code 처럼 서브에이전트를 쓸 수 있는 환경이면, 경로마다 서브에이전트에게 맡겨 나란히 조사해도 됩니다.

                ## 3. 검증 (Verifier 역할)
                조사가 끝나면 입장을 바꿔, 기록한 발견마다 "이 보고서는 틀렸을 수 있다"고 보고 독립적으로 다시 확인합니다.
                - 입력 출처: 정말 외부 사용자가 조절할 수 있는 값인가?
                - 도달 가능성: 진입점이 실제로 노출되고, 호출 경로의 각 단계가 실제로 이어지는가?
                - 방어 장치: 위의 장치 중 하나라도 공격을 막는가?
                - 영향: 성공하면 실제로 무엇을 할 수 있는가? 심각도가 과장되지 않았는가?
                판단이 서면 submit_verdict 로 confirmed / rejected / uncertain 을 기록합니다. uncertain 은 저장소에 근거 코드가 없을 때만 씁니다.
                서브에이전트를 쓸 수 있으면, 조사와 다른 서브에이전트에게 검증을 맡겨 판단이 섞이지 않게 합니다.

                ## 4. 보고
                export_report(format=markdown) 로 보고서를 저장하고, 확정된 취약점을 심각도 순으로 요약해 주세요.
                각 항목에 위치(파일:줄), 공격 예시, 고치는 방법을 짧게 붙입니다. 기각한 발견은 왜 오탐인지 한 줄씩 덧붙입니다.
                """.formatted(target, load, maxPaths);
    }

    static String verifyFindings(String repo) {
        return """
                저장소 %s 의 검증 대기 발견을 다시 검증해 주세요. 모든 설명은 한국어로 씁니다.
                list_findings(repo="%s", status="OPEN", detail=true) 로 목록을 보고, 발견마다 보고서를 그대로 믿지 말고
                read_file·grep_code·get_callers 로 코드를 직접 다시 읽어 입력 출처, 도달 가능성, 방어 장치, 영향을 확인합니다.
                판단이 서면 submit_verdict 로 confirmed / rejected / uncertain 을 기록하고, 끝나면 판정 결과를 표로 요약해 주세요.
                """.formatted(repo, repo);
    }
}
